%% The reverse proxy of the redirect listener (`server.upstream`): the
%% requests its handler leaves to the upstream (`Forward`), forwarded by
%% the connection process of `redirect_proxy_http`, whose connection
%% record, logging and responses it shares.
%%
%% The connection process forwards the request itself: it opens one upstream
%% connection (lazily, on the first forwarded request) and reuses it while
%% both sides keep their connection alive, so that pipelined requests are
%% still answered in order. The request head is re-encoded (hop-by-hop
%% headers dropped, `x-forwarded-*` set by the handler), its body streamed
%% (re-chunked, so that the upstream never sees framing it could read
%% differently), then the response head relayed and its body streamed back.
%% `upstream_timeout` is the wait for the response head, and the idle
%% timeout of every read and write.
%%
%% Between requests the upstream socket is armed (`{active, once}`): if the
%% upstream closes the connection, or sends bytes nothing asked for, a
%% message says so, and the next request, seeing it, opens a new connection
%% instead (no call to the socket to find out). The first bytes of the
%% response come as that message; the socket is passive for the rest of the
%% exchange, and armed again when the connection is kept.
-module(redirect_proxy_upstream).

-include("redirect_proxy_http.hrl").

%% for redirect_proxy_http
-export([forward/7, upstream_settings/1, close_upstream/1, up_await/2]).

%% the connection loop, responses, logging and the parser's helpers of
%% redirect_proxy_http (remote calls)
-import(redirect_proxy_http, [
    request/2, close/1, reject/2, linger_close/1, date/1, limited/2,
    close_requested/2, has_token/2, lowercase/1, lowercase_name/1, name/3,
    token/2, skip_ows/1
]).

%% The upstream, resolved when the listener starts.
-record(up, {
    tls,
    %% an IP tuple, or a host name to resolve on each connect
    address,
    port,
    timeout,
    %% request bodies longer than this get a 413 (0: no limit)
    max_body,
    %% `host[:port]`, sent when the client sent no Host
    authority,
    %% for the log
    url,
    tls_options
}).

-define(CONNECT_TIMEOUT, 5000).
%% the process dictionary key of the bytes a relayed response has yet to
%% send to the client (relay_body/6)
-define(RELAYED, '$redirect_proxy_relayed').
-define(MAX_RESPONSE_HEAD, 65536).
%% 1xx responses relayed before a final one: an upstream sending them
%% without end would keep the request waiting
-define(MAX_INTERIM, 10).
%% process dictionary key: payload bytes of the chunked request body so far

%% headers that only concern one connection (RFC 9110 7.6.1), and the ones
%% the server sets itself
-define(HOP_BY_HOP(N),
    (N =:= <<"connection">> orelse N =:= <<"keep-alive">>
     orelse N =:= <<"proxy-connection">> orelse N =:= <<"te">>
     orelse N =:= <<"trailer">> orelse N =:= <<"transfer-encoding">>
     orelse N =:= <<"upgrade">>)).

%% One forwarded request.
-record(fwd, {
    method,
    %% the request head sent upstream (iodata)
    head,
    %% none | {length, N} | chunked
    body,
    %% `Expect: 100-continue` from an HTTP/1.1 client with a body
    continue,
    %% none | the `Upgrade` header the client asked for (with
    %% `Connection: upgrade`)
    upgrade,
    %% the client asked to close its connection after the response
    client_close,
    %% draining: close the client connection after the response
    close_after,
    version,
    done,
    %% a request without a body that may be sent again on a new connection
    %% when a reused one turns out to be closed
    retry,
    %% 1xx responses read so far
    interim = 0
}).

%% The request a handler leaves to the upstream.
forward(_, _, _, _, _, Done, #conn{upstream = none} = C) ->
    done(Done, 502, 0, {some, unreachable}),
    reject(502, C);
forward(Request, Version, Rest, CloseAfter, {XForwarded, Dropped}, Done, C) ->
    {request, Method, Headers, _, _, _, _, Path, Query} = Request,
    case framing(Headers, Version) of
        {error, Status} ->
            done(Done, Status, 0, none),
            reject(Status, C);
        {ok, {length, N}, _, _, _, _} when N > C#conn.upstream#up.max_body,
                                           C#conn.upstream#up.max_body > 0 ->
            done(Done, 413, 0, none),
            reject(413, C);
        {ok, Body, Tokens, Upgrade, Expect, HasHost} ->
            Up = C#conn.upstream,
            %% the client's values of the headers the handler sets, and of
            %% the ones it drops (forwarding headers from untrusted peers)
            %% in the form request_headers/2 compares (`_` read as `-`)
            Drop = [dashed(N) || N <- [T || T <- Tokens, not essential(T)]
                ++ [N || {N, _} <- XForwarded] ++ Dropped],
            HasBody = Body =/= none andalso Body =/= {length, 0},
            Head = [method_name(Method), $\s, Path,
                    case Query of none -> []; {some, Q} -> [$?, Q] end,
                    <<" HTTP/1.1\r\n">>,
                    case HasHost of
                        true -> [];
                        false -> [<<"host: ">>, Up#up.authority, <<"\r\n">>]
                    end,
                    request_headers(Headers, Drop),
                    [[N, <<": ">>, V, <<"\r\n">>] || {N, V} <- XForwarded],
                    case Upgrade of
                        none -> [];
                        _ -> [<<"connection: upgrade\r\nupgrade: ">>, Upgrade, <<"\r\n">>]
                    end,
                    %% one framing header, normalised
                    case Body of
                        chunked -> <<"transfer-encoding: chunked\r\n">>;
                        {length, N} -> [<<"content-length: ">>, integer_to_binary(N), <<"\r\n">>];
                        none -> []
                    end,
                    <<"\r\n">>],
            F = #fwd{
                method = Method,
                head = Head,
                body = Body,
                continue = Expect andalso HasBody andalso Version =:= {1, 1},
                upgrade = Upgrade,
                client_close = close_requested(Version, join(Tokens)),
                close_after = CloseAfter,
                version = Version,
                done = Done,
                retry = not HasBody andalso Upgrade =:= none andalso idempotent(Method)
            },
            case open(C) of
                {ok, Socket, Reused, C1} -> send_request(Socket, Reused, Rest, F, C1);
                {error, Reason} -> fail(502, unreachable, Reason, F, C)
            end
    end.

%% {ok, Body, ConnectionTokens, Upgrade, Expect, HasHost} | {error, Status}
%%
%% The framing of the request body (RFC 9112 6): `Transfer-Encoding` and
%% `Content-Length` together, a transfer coding other than chunked, a
%% `Transfer-Encoding` in an HTTP/1.0 request, and an invalid or ambiguous
%% length are rejected rather than guessed. HTTP/1.0 requests cannot
%% upgrade (RFC 9110 7.8), and an upgrade to HTTP/2 over cleartext (`h2c`)
%% is not offered to the upstream: the request is forwarded as an ordinary
%% one, since an HTTP/2 connection behind the proxy would bypass its
%% checks.
framing(Headers, Version) ->
    framing(Headers, Version, [], [], [], none, false, false).

framing([{Name, Value} | Rest], V, Lengths, Codings, Tokens, Upgrade, Expect, Host) ->
    case Name of
        <<"content-length">> ->
            framing(Rest, V, [Value | Lengths], Codings, Tokens, Upgrade, Expect, Host);
        <<"transfer-encoding">> ->
            framing(Rest, V, Lengths, [Value | Codings], Tokens, Upgrade, Expect, Host);
        <<"connection">> ->
            framing(Rest, V, Lengths, Codings, tokens(Value) ++ Tokens, Upgrade, Expect, Host);
        <<"upgrade">> ->
            framing(Rest, V, Lengths, Codings, Tokens, Value, Expect, Host);
        <<"expect">> ->
            framing(Rest, V, Lengths, Codings, Tokens, Upgrade,
                    Expect orelse has_token(Value, <<"100-continue">>), Host);
        <<"host">> ->
            framing(Rest, V, Lengths, Codings, Tokens, Upgrade, Expect, true);
        _ ->
            framing(Rest, V, Lengths, Codings, Tokens, Upgrade, Expect, Host)
    end;
framing([], Version, Lengths, Codings, Tokens, Upgrade0, Expect, Host) ->
    Upgrade = case Version =:= {1, 1} andalso lists:member(<<"upgrade">>, Tokens)
                   andalso Upgrade0 =/= none andalso not has_token(Upgrade0, <<"h2c">>) of
        true -> Upgrade0;
        false -> none
    end,
    case {Lengths, Codings} of
        {[], []} ->
            {ok, none, Tokens, Upgrade, Expect, Host};
        {[], _} when Version =:= {1, 0} ->
            {error, 400};
        {[], _} ->
            case tokens(join(lists:reverse(Codings))) of
                [<<"chunked">>] -> {ok, chunked, Tokens, Upgrade, Expect, Host};
                _ -> {error, 400}
            end;
        {_, []} ->
            case content_length(Lengths) of
                {ok, N} -> {ok, {length, N}, Tokens, Upgrade, Expect, Host};
                error -> {error, 400}
            end;
        _ ->
            {error, 400}
    end.

%% The length of one or more `Content-Length` values: the same digits
%% everywhere (`5, 5` is 5).
content_length(Values) ->
    case lists:usort([trim(V) || Value <- Values, V <- binary:split(Value, <<",">>, [global])]) of
        [Digits] when byte_size(Digits) > 0, byte_size(Digits) =< 18 ->
            case lists:all(fun(D) -> D >= $0 andalso D =< $9 end, binary_to_list(Digits)) of
                true -> {ok, binary_to_integer(Digits)};
                false -> error
            end;
        _ ->
            error
    end.

%% Lowercase items of a comma-separated header value.
tokens(Value) ->
    [lowercase(T) || Item <- binary:split(Value, <<",">>, [global]),
                     T <- [trim(Item)], T =/= <<>>].

join([]) -> <<>>;
join(Items) -> iolist_to_binary(lists:join(<<",">>, Items)).

%% Headers a `Connection` header cannot remove: dropping the framing or the
%% host would make the other side read another message than the one checked.
essential(<<"host">>) -> true;
essential(<<"content-length">>) -> true;
essential(<<"transfer-encoding">>) -> true;
essential(_) -> false.

%% The client's headers, without the hop-by-hop ones, `Expect` (answered
%% here), `Content-Length` (sent once, normalised) and the ones in Drop:
%% named by its `Connection` header, set or dropped by the handler. Some
%% servers read `_` in a header name as `-` (CGI variables): `x_real_ip`
%% is dropped with `x-real-ip`, and `transfer_encoding` or
%% `content_length` with the framing headers (next to the normalised ones,
%% they would give such an upstream two framings of one body).
request_headers([{Name, Value} | Rest], Drop) ->
    case dropped(dashed(Name), Drop) of
        true -> request_headers(Rest, Drop);
        false -> [Name, <<": ">>, Value, <<"\r\n">> | request_headers(Rest, Drop)]
    end;
request_headers([], _) ->
    [].

dashed(Name) ->
    case binary:match(Name, <<"_">>) of
        nomatch -> Name;
        _ -> binary:replace(Name, <<"_">>, <<"-">>, [global])
    end.

dropped(Name, _) when ?HOP_BY_HOP(Name) -> true;
dropped(<<"expect">>, _) -> true;
dropped(<<"content-length">>, _) -> true;
dropped(Name, Drop) -> lists:member(Name, Drop).

method_name(get) -> <<"GET">>;
method_name(head) -> <<"HEAD">>;
method_name(post) -> <<"POST">>;
method_name(put) -> <<"PUT">>;
method_name(delete) -> <<"DELETE">>;
method_name(options) -> <<"OPTIONS">>;
method_name(patch) -> <<"PATCH">>;
method_name(trace) -> <<"TRACE">>;
method_name(connect) -> <<"CONNECT">>;
method_name({other, Method}) -> Method.

idempotent(Method) ->
    Method =:= get orelse Method =:= head orelse Method =:= options
        orelse Method =:= trace orelse Method =:= put orelse Method =:= delete.

%% Sends the request head and body, then relays the response.
send_request(Socket, Reused, Rest, F, C) ->
    case up_send(Socket, F#fwd.head) of
        ok ->
            case F#fwd.continue of
                true -> _ = gen_tcp:send(C#conn.socket, <<"HTTP/1.1 100 Continue\r\n\r\n">>);
                false -> ok
            end,
            case send_body(F#fwd.body, Rest, Socket, C) of
                {ok, Rest1} ->
                    response(Socket, Reused, armed, Rest1, true, F, C);
                {error, {upstream, _}} ->
                    %% the upstream may have answered without reading the
                    %% whole body: relay its answer, then close
                    response(Socket, false, armed, <<>>, false, F#fwd{retry = false}, C);
                {error, {client, timeout}} ->
                    done(F#fwd.done, 408, 0, none),
                    reject(408, C);
                {error, too_large} ->
                    done(F#fwd.done, 413, 0, none),
                    reject(413, C);
                {error, {client, _}} ->
                    %% the client went away before its request was complete
                    done(F#fwd.done, 499, 0, none),
                    close(C);
                {error, bad_chunk} ->
                    done(F#fwd.done, 400, 0, none),
                    reject(400, C)
            end;
        {error, _} when Reused, F#fwd.retry ->
            again(Rest, F, C);
        {error, Reason} ->
            fail(502, invalid_response, Reason, F, C)
    end.

%% Sends the request again on a new connection: the reused one was closed.
again(Rest, F, C) ->
    C1 = close_upstream(C),
    case connect(C1#conn.upstream) of
        {ok, Socket} ->
            send_request(Socket, false, Rest, F#fwd{retry = false}, C1#conn{up = Socket});
        {error, Reason} ->
            fail(502, unreachable, Reason, F, C1)
    end.

%% {ok, Rest} | {error, {client | upstream, Reason}} | {error, bad_chunk}
send_body(none, Rest, _, _) ->
    {ok, Rest};
send_body({length, N}, Rest, Socket, C) ->
    case copy_length(Rest, N, client_recv(C), upstream_emit(Socket), 0) of
        {ok, Rest1, _} -> {ok, Rest1};
        {error, Reason, _} -> {error, Reason}
    end;
send_body(chunked, Rest, Socket, C) ->
    Emit = upstream_emit(Socket),
    Chunk = body_limit(chunk_emit(Emit), C#conn.upstream#up.max_body),
    case copy_chunked(Rest, client_recv(C), Chunk, 0) of
        {ok, Rest1, _} ->
            case Emit(<<"0\r\n\r\n">>) of
                ok -> {ok, Rest1};
                Error -> Error
            end;
        {error, Reason, _} ->
            {error, Reason}
    end.

%% Reads the response head (after 1xx interim responses), then relays it.
%% Buffer: the bytes read after the previous head, or `armed` for the first
%% read (the message of the armed socket). BodyDone: the whole request body
%% was sent.
response(Socket, Reused, Buffer, Rest, BodyDone, F, #conn{upstream = Up} = C) ->
    case read_head(Socket, Buffer, Up#up.timeout) of
        {ok, 101, Reason, _, Headers, Buffer1} when F#fwd.upgrade =/= none, BodyDone ->
            case switched(Headers, F#fwd.upgrade) of
                true -> tunnel(Socket, Reason, Headers, Buffer1, Rest, F, C);
                false -> fail(502, invalid_response, unexpected_upgrade, F, C)
            end;
        {ok, 101, _, _, _, _} ->
            fail(502, invalid_response, unexpected_upgrade, F, C);
        {ok, Status, _, _, _, _} when Status < 200, F#fwd.interim >= ?MAX_INTERIM ->
            fail(502, invalid_response, too_many_interim_responses, F, C);
        {ok, Status, Reason, _, Headers, Buffer1} when Status < 200 ->
            %% interim responses (103 Early Hints...); the 100 Continue of
            %% the upstream is not: the client already got one
            case Status =/= 100 andalso F#fwd.version =:= {1, 1} of
                true ->
                    _ = gen_tcp:send(C#conn.socket, [
                        status_line(Status, Reason),
                        response_headers(Headers, [], false), <<"\r\n">>]);
                false ->
                    ok
            end,
            response(Socket, false, Buffer1, Rest, BodyDone,
                     F#fwd{interim = F#fwd.interim + 1}, C);
        {ok, Status, Reason, Minor, Headers, Buffer1} ->
            relay(Socket, Status, Reason, Minor, Headers, Buffer1, Rest, BodyDone, F, C);
        {error, closed} when Reused, F#fwd.retry ->
            again(Rest, F, C);
        {error, timeout} ->
            fail(504, timed_out, timeout, F, C);
        {error, Reason} ->
            fail(502, invalid_response, Reason, F, C)
    end.

relay(Socket, Status, Reason, Minor, Headers, Buffer, Rest, BodyDone, F, C) ->
    {Lengths, Codings, Tokens, HasDate} = response_fields(Headers, [], [], [], false),
    %% Framing, and the transfer codings other than chunked, which are
    %% relayed (the body is re-chunked)
    {Framing, Kept} = if
        F#fwd.method =:= head; Status =:= 204; Status =:= 304 -> {none, []};
        Codings =/= [] ->
            Applied = tokens(join(lists:reverse(Codings))),
            case lists:reverse(Applied) of
                [<<"chunked">> | Others] -> {chunked, lists:reverse(Others)};
                %% a final coding other than chunked: delimited by the end
                %% of the connection
                _ -> {close, Applied}
            end;
        Lengths =/= [] ->
            case content_length(Lengths) of
                {ok, N} -> {{length, N}, []};
                error -> {invalid, []}
            end;
        true -> {close, []}
    end,
    case Framing of
        invalid ->
            fail(502, invalid_response, invalid_content_length, F, C);
        _ when Kept =/= [], F#fwd.version =:= {1, 0} ->
            %% an HTTP/1.0 client has no transfer codings
            fail(502, invalid_response, transfer_coding_for_http_1_0, F, C);
        _ ->
            Chunked = Framing =:= chunked andalso F#fwd.version =:= {1, 1},
            ClientKeep = BodyDone andalso not F#fwd.client_close
                andalso not F#fwd.close_after
                andalso (Chunked orelse delimited(Framing)),
            UpKeep = BodyDone andalso Framing =/= close
                andalso not lists:member(<<"close">>, Tokens)
                andalso (Minor =:= 1 orelse lists:member(<<"keep-alive">>, Tokens))
                andalso not (Codings =/= [] andalso Lengths =/= []),
            %% A Date nominated by Connection is removed below, so it
            %% cannot suppress the locally generated replacement.
            {Date, C1} = case HasDate andalso not lists:member(<<"date">>, Tokens) of
                true -> {[], C};
                false ->
                    {D, Cd} = date(C),
                    {[<<"date: ">>, D, <<"\r\n">>], Cd}
            end,
            Head = [status_line(Status, Reason),
                    response_headers(Headers, Tokens, Codings =/= []),
                    Date,
                    case {Chunked, Kept} of
                        {true, _} ->
                            [<<"transfer-encoding: ">>,
                             lists:join(<<", ">>, Kept ++ [<<"chunked">>]), <<"\r\n">>];
                        {false, []} ->
                            [];
                        {false, _} ->
                            [<<"transfer-encoding: ">>, lists:join(<<", ">>, Kept), <<"\r\n">>]
                    end,
                    case {ClientKeep, F#fwd.version} of
                        {false, _} -> <<"connection: close\r\n">>;
                        {true, {1, 0}} -> <<"connection: keep-alive\r\n">>;
                        {true, _} -> []
                    end,
                    <<"\r\n">>],
            case relay_body(Framing, Chunked, Head, Buffer, Socket, C1) of
                {ok, Left, Bytes} ->
                    done(F#fwd.done, Status, Bytes, none),
                    %% kept: armed until the next request
                    C2 = case UpKeep andalso Left =:= <<>>
                              andalso up_setopts(Socket, [{active, once}]) =:= ok of
                        true -> C1;
                        false -> close_upstream(C1)
                    end,
                    case {ClientKeep, BodyDone} of
                        {true, _} -> request(Rest, C2);
                        {false, true} -> close(C2);
                        %% the upstream answered without reading the whole
                        %% body: the client may still be sending it
                        {false, false} -> linger_close(C2)
                    end;
                {error, Why, Bytes} ->
                    Error = case Why of
                        {upstream, timeout} ->
                            warn(C1, "timed out while relaying a response", []),
                            {some, timed_out};
                        {upstream, _} ->
                            warn(C1, "closed while relaying a response", []),
                            {some, invalid_response};
                        bad_chunk ->
                            warn(C1, "sent an invalid chunked response", []),
                            {some, invalid_response};
                        {client, _} ->
                            none
                    end,
                    %% the client did not get the whole response
                    Logged = case Why of
                        {client, _} -> 499;
                        _ -> Status
                    end,
                    done(F#fwd.done, Logged, Bytes, Error),
                    close(C1)
            end
    end.

%% Whether the end of a response is known without the end of the connection.
delimited(none) -> true;
delimited({length, _}) -> true;
delimited(_) -> false.

%% Sends the response head and relays the body: {ok, UpstreamLeftover,
%% Bytes} | {error, Reason, Bytes}, Bytes the body bytes sent to the client.
%%
%% What is to be sent to the client (the head, then what the copy emits) is
%% gathered under ?RELAYED in the process dictionary, with the number of
%% body bytes in it, and sent before each wait for more bytes from the
%% upstream, and at the end: the head and the body bytes read with it go in
%% one send, a small response in one segment.
relay_body(Framing, Chunked, Head, Buffer, Socket, C) ->
    put(?RELAYED, {Head, 0}),
    Read = upstream_recv(Socket, C),
    Recv = fun() ->
        case flush(C) of
            ok -> Read();
            Error -> Error
        end
    end,
    Result = copy_body(Framing, Chunked, Buffer, Recv),
    %% what was read is sent, even when the rest cannot be
    Flushed = flush(C),
    %% the body bytes a failed send dropped
    {_, Unsent} = erase(?RELAYED),
    case {Result, Flushed} of
        {{ok, _, Bytes}, {error, Reason}} -> {error, Reason, Bytes - Unsent};
        {{error, Reason, Bytes}, _} -> {error, Reason, Bytes - Unsent};
        _ -> Result
    end.

copy_body(none, _, Buffer, _) ->
    {ok, Buffer, 0};
copy_body({length, N}, _, Buffer, Recv) ->
    copy_length(Buffer, N, Recv, fun relayed/1, 0);
copy_body(chunked, true, Buffer, Recv) ->
    case copy_chunked(Buffer, Recv, fun relayed_chunk/1, 0) of
        {ok, Left, Bytes} ->
            gather(<<"0\r\n\r\n">>, 0),
            {ok, Left, Bytes};
        Error ->
            Error
    end;
copy_body(chunked, false, Buffer, Recv) ->
    %% an HTTP/1.0 client: the body without its chunks, then the end of the
    %% connection
    copy_chunked(Buffer, Recv, fun relayed/1, 0);
copy_body(close, _, Buffer, Recv) ->
    copy_close(Buffer, Recv, fun relayed/1, 0).

%% The emitters of relay_body/6: body bytes, as they are or in a chunk.
relayed(Data) ->
    gather(Data, byte_size(Data)).

relayed_chunk(Data) ->
    gather([integer_to_binary(byte_size(Data), 16), <<"\r\n">>, Data, <<"\r\n">>],
           byte_size(Data)).

gather(Data, Bytes) ->
    {Pending, Unsent} = get(?RELAYED),
    put(?RELAYED, {[Pending | Data], Unsent + Bytes}),
    ok.

%% Sends what relay_body/6 gathered: ok | {error, {client, Reason}}. A failed
%% send keeps the count of the body bytes it dropped.
flush(#conn{socket = Socket}) ->
    case get(?RELAYED) of
        {[], _} ->
            ok;
        {Pending, Unsent} ->
            case gen_tcp:send(Socket, Pending) of
                ok ->
                    put(?RELAYED, {[], 0}),
                    ok;
                {error, Reason} ->
                    put(?RELAYED, {[], Unsent}),
                    {error, {client, Reason}}
            end
    end.

%% {Lengths, Codings, ConnectionTokens, HasDate} of a response.
response_fields([{_, Lower, Value} | Rest], Lengths, Codings, Tokens, Date) ->
    case Lower of
        <<"content-length">> -> response_fields(Rest, [Value | Lengths], Codings, Tokens, Date);
        <<"transfer-encoding">> -> response_fields(Rest, Lengths, [Value | Codings], Tokens, Date);
        <<"connection">> -> response_fields(Rest, Lengths, Codings, tokens(Value) ++ Tokens, Date);
        <<"date">> -> response_fields(Rest, Lengths, Codings, Tokens, true);
        _ -> response_fields(Rest, Lengths, Codings, Tokens, Date)
    end;
response_fields([], Lengths, Codings, Tokens, Date) ->
    {Lengths, Codings, Tokens, Date}.

%% The upstream's headers without the hop-by-hop ones and the ones its
%% `Connection` header names (Tokens; `false` keeps `Connection` and
%% `Upgrade`, for a 101), and without `Content-Length` next to a
%% `Transfer-Encoding` (RFC 9112 6.3).
response_headers([{Name, Lower, Value} | Rest], Tokens, DropLength) ->
    Drop = case Tokens of
        false ->
            Lower =/= <<"connection">> andalso Lower =/= <<"upgrade">>
                andalso ?HOP_BY_HOP(Lower);
        _ ->
            ?HOP_BY_HOP(Lower)
                orelse (lists:member(Lower, Tokens) andalso not essential(Lower))
                orelse (DropLength andalso Lower =:= <<"content-length">>)
    end,
    case Drop of
        true -> response_headers(Rest, Tokens, DropLength);
        false -> [Name, <<": ">>, Value, <<"\r\n">> | response_headers(Rest, Tokens, DropLength)]
    end;
response_headers([], _, _) ->
    [].

%% {ok, Status, Reason, Minor, Headers, Rest} | {error, timeout | closed | Reason}
read_head(Socket, armed, Timeout) ->
    case up_await(Socket, Timeout) of
        {ok, Data} -> read_head(Socket, Data, Timeout);
        {error, timeout} -> {error, timeout};
        {error, _} -> {error, closed}
    end;
read_head(Socket, Buffer, Timeout) ->
    case binary:match(Buffer, [<<"\r\n\r\n">>, <<"\n\n">>]) of
        {At, Length} ->
            <<Head:At/binary, _:Length/binary, Rest/binary>> = Buffer,
            case parse_response(Head) of
                {ok, Status, Reason, Minor, Headers} -> {ok, Status, Reason, Minor, Headers, Rest};
                error -> {error, invalid_response_head}
            end;
        nomatch when byte_size(Buffer) > ?MAX_RESPONSE_HEAD ->
            {error, response_head_too_large};
        nomatch ->
            case up_recv(Socket, Timeout) of
                {ok, Data} -> read_head(Socket, <<Buffer/binary, Data/binary>>, Timeout);
                {error, timeout} -> {error, timeout};
                {error, _} when Buffer =:= <<>> -> {error, closed};
                {error, _} -> {error, incomplete_response_head}
            end
    end.

%% {ok, Status, Reason, Minor, Headers} | error, Headers being
%% [{Name, LowercaseName, Value}]: the name as sent, and lowercased once
parse_response(Head) ->
    case binary:split(Head, [<<"\r\n">>, <<"\n">>], [global]) of
        [<<"HTTP/1.", Minor, $\s, A, B, D, Tail/binary>> | Lines]
          when (Minor =:= $0 orelse Minor =:= $1),
               A >= $1, A =< $5, B >= $0, B =< $9, D >= $0, D =< $9 ->
            Reason = case Tail of
                <<$\s, R/binary>> -> R;
                <<>> -> <<>>;
                _ -> <<0>>
            end,
            case printable(Reason) andalso response_lines(Lines, []) of
                {ok, Headers} ->
                    {ok, (A - $0) * 100 + (B - $0) * 10 + (D - $0), Reason, Minor - $0, Headers};
                _ ->
                    error
            end;
        _ ->
            error
    end.

response_lines([], Acc) ->
    {ok, lists:reverse(Acc)};
response_lines([Line | Rest], Acc) ->
    case name(Line, 0, false) of
        {Length, Upper} when Length > 0 ->
            <<Name:Length/binary, $:, Value/binary>> = Line,
            Lower = case Upper of
                true -> lowercase_name(Name);
                false -> Name
            end,
            %% a lone CR would end the line for some clients
            case printable(Value) of
                true -> response_lines(Rest, [{Name, Lower, trim(Value)} | Acc]);
                false -> error
            end;
        _ ->
            error
    end.

%% Whether a reason phrase or header value has no control character other
%% than HTAB (RFC 9110 5.5, RFC 9112 4).
printable(<<C, _/binary>>) when C < 32, C =/= $\t; C =:= 127 -> false;
printable(<<_, Rest/binary>>) -> printable(Rest);
printable(<<>>) -> true.

%% Whether the `Upgrade` header of a 101 names only protocols the client
%% asked for (RFC 9110 7.8), compared without case.
switched(Headers, Requested) ->
    Asked = tokens(Requested),
    case [P || {_, <<"upgrade">>, Value} <- Headers, P <- tokens(Value)] of
        [] -> false;
        Protocols -> lists:all(fun(P) -> lists:member(P, Asked) end, Protocols)
    end.

%% A 101 from the upstream: the response is relayed, then bytes are copied
%% both ways until either side closes, or none flows for upstream_timeout.
tunnel(Socket, Reason, Headers, Buffer, Rest, F, #conn{socket = Client, upstream = Up} = C) ->
    Head = [status_line(101, Reason), response_headers(Headers, false, false), <<"\r\n">>],
    Bytes = case gen_tcp:send(Client, [Head | Buffer]) of
        ok ->
            case Rest =:= <<>> orelse up_send(Socket, Rest) =:= ok of
                true ->
                    _ = up_setopts(Socket, [{active, ?ACTIVE}]),
                    tunnel_loop(Client, Socket, Up#up.timeout, byte_size(Buffer));
                false ->
                    byte_size(Buffer)
            end;
        {error, _} ->
            0
    end,
    done(F#fwd.done, 101, Bytes, none),
    close(C).

tunnel_loop(Client, {_, Raw} = Socket, Timeout, Bytes) ->
    receive
        {tcp, Client, Data} ->
            case up_send(Socket, Data) of
                ok -> tunnel_loop(Client, Socket, Timeout, Bytes);
                {error, _} -> Bytes
            end;
        {tcp_passive, Client} ->
            _ = inet:setopts(Client, [{active, ?ACTIVE}]),
            tunnel_loop(Client, Socket, Timeout, Bytes);
        {Tag, Raw, Data} when Tag =:= tcp; Tag =:= ssl ->
            case gen_tcp:send(Client, Data) of
                ok -> tunnel_loop(Client, Socket, Timeout, Bytes + byte_size(Data));
                {error, _} -> Bytes
            end;
        {Tag, Raw} when Tag =:= tcp_passive; Tag =:= ssl_passive ->
            _ = up_setopts(Socket, [{active, ?ACTIVE}]),
            tunnel_loop(Client, Socket, Timeout, Bytes);
        {tcp_closed, Client} ->
            Bytes;
        {tcp_error, Client, _} ->
            Bytes;
        {Tag, Raw} when Tag =:= tcp_closed; Tag =:= ssl_closed ->
            Bytes;
        {Tag, Raw, _} when Tag =:= tcp_error; Tag =:= ssl_error ->
            Bytes
    after Timeout ->
        Bytes
    end.

%% An upstream failure before anything was relayed: an empty 502 or 504, and
%% the client connection closed.
fail(Status, Error, Reason, F, C) ->
    warn(C, "~ts", [describe_failure(Reason)]),
    done(F#fwd.done, Status, 0, {some, Error}),
    reject(Status, C).

describe_failure(timeout) -> <<"no response in time">>;
describe_failure(closed) -> <<"closed the connection without a response">>;
describe_failure(econnrefused) -> <<"connection refused">>;
describe_failure(nxdomain) -> <<"unknown host">>;
describe_failure(Reason) -> iolist_to_binary(io_lib:format("~0p", [Reason])).

done(Done, Status, Bytes, Error) ->
    try
        Done({forwarded, Status, Bytes, Error})
    catch
        Class:Reason:Stack ->
            logger:error(iolist_to_binary(io_lib:format(
                "redirect listener forward callback failed: ~0p: ~0p~n~0p",
                [Class, Reason, Stack])))
    end.

%% A warning about the upstream, at most one a second for the whole node:
%% an upstream that is down must not flood the log.
warn(#conn{upstream = Up}, Format, Args) ->
    limited(?UPSTREAM_LOG, fun() ->
        logger:warning(iolist_to_binary(io_lib:format(
            "upstream ~ts: " ++ Format ++ " (at most one such warning a second is logged)",
            [Up#up.url | Args])))
    end).

%% Body copies. Recv() -> {ok, Data} | {error, Reason};
%% Emit(Data) -> ok | {error, Reason}. They return {ok, Rest, Bytes} (Rest:
%% the bytes after the body) or {error, Reason, Bytes}, Bytes being the
%% payload emitted.

copy_length(Buffer, N, _, Emit, Bytes) when byte_size(Buffer) >= N ->
    <<Data:N/binary, Rest/binary>> = Buffer,
    case emit(Emit, Data) of
        ok -> {ok, Rest, Bytes + N};
        {error, Reason} -> {error, Reason, Bytes}
    end;
copy_length(Buffer, N, Recv, Emit, Bytes) ->
    case emit(Emit, Buffer) of
        ok ->
            Size = byte_size(Buffer),
            case Recv() of
                {ok, Data} -> copy_length(Data, N - Size, Recv, Emit, Bytes + Size);
                {error, Reason} -> {error, Reason, Bytes + Size}
            end;
        {error, Reason} ->
            {error, Reason, Bytes}
    end.

%% Until the upstream closes the connection.
copy_close(Buffer, Recv, Emit, Bytes) ->
    case emit(Emit, Buffer) of
        ok ->
            case Recv() of
                {ok, Data} -> copy_close(Data, Recv, Emit, Bytes + byte_size(Buffer));
                {error, {upstream, closed}} -> {ok, <<>>, Bytes + byte_size(Buffer)};
                {error, Reason} -> {error, Reason, Bytes + byte_size(Buffer)}
            end;
        {error, Reason} ->
            {error, Reason, Bytes}
    end.

%% A chunked body (RFC 9112 7.1), its payload emitted: extensions and
%% trailers are dropped.
copy_chunked(Buffer, Recv, Emit, Bytes) ->
    case chunk_size(Buffer) of
        {ok, 0, Rest} -> trailers(Rest, Recv, Bytes, 0);
        {ok, Size, _} when is_tuple(Emit), Bytes + Size > element(2, Emit) ->
            {error, too_large, Bytes};
        {ok, Size, Rest} -> chunk_data(Rest, Size, Recv, Emit, Bytes);
        more -> refill(Buffer, Recv, Bytes, fun(B) -> copy_chunked(B, Recv, Emit, Bytes) end);
        error -> {error, bad_chunk, Bytes}
    end.

%% The chunk-size line, strictly (RFC 9112 7.1.1): hex digits, chunk
%% extensions made of tokens and quoted strings, then CRLF. Anything else
%% (a bare LF, a lone CR, control characters, junk around the size, a size
%% of more than 15 digits) is an error: a body another parser could frame
%% differently is not forwarded.
chunk_size(Buffer) ->
    case binary:match(Buffer, <<"\n">>) of
        nomatch when byte_size(Buffer) > 4096 ->
            error;
        nomatch ->
            more;
        {At, 1} when At > 0 ->
            Length = At - 1,
            case Buffer of
                <<Line:Length/binary, "\r\n", Rest/binary>> ->
                    case hex(Line, 0, 0) of
                        {ok, Size} -> {ok, Size, Rest};
                        error -> error
                    end;
                _ ->
                    error
            end;
        _ ->
            error
    end.

hex(<<C, Rest/binary>>, N, Digits) when Digits < 15, C >= $0, C =< $9 ->
    hex(Rest, N * 16 + C - $0, Digits + 1);
hex(<<C, Rest/binary>>, N, Digits) when Digits < 15, C >= $a, C =< $f ->
    hex(Rest, N * 16 + C - $a + 10, Digits + 1);
hex(<<C, Rest/binary>>, N, Digits) when Digits < 15, C >= $A, C =< $F ->
    hex(Rest, N * 16 + C - $A + 10, Digits + 1);
hex(Rest, N, Digits) when Digits > 0 ->
    case extensions(Rest) of
        true -> {ok, N};
        false -> error
    end;
hex(_, _, _) ->
    error.

%% *( BWS ";" BWS ext-name [ BWS "=" BWS ( token / quoted-string ) ] )
extensions(Bin) ->
    case skip_ows(Bin) of
        <<>> -> true;
        <<$;, Rest/binary>> ->
            case token(skip_ows(Rest), 0) of
                {0, _} ->
                    false;
                {Length, _} ->
                    <<_:Length/binary, After/binary>> = skip_ows(Rest),
                    case skip_ows(After) of
                        <<$=, Value/binary>> -> extension_value(skip_ows(Value));
                        Next -> extensions(Next)
                    end
            end;
        _ ->
            false
    end.

extension_value(<<$", Rest/binary>>) ->
    quoted(Rest);
extension_value(Bin) ->
    case token(Bin, 0) of
        {0, _} -> false;
        {Length, _} ->
            <<_:Length/binary, Rest/binary>> = Bin,
            extensions(Rest)
    end.

%% The rest of a quoted string: qdtext or quoted-pair, then `"`.
quoted(<<$", Rest/binary>>) -> extensions(Rest);
quoted(<<$\\, C, Rest/binary>>) when C =:= $\t; C >= 32, C =/= 127 -> quoted(Rest);
quoted(<<C, Rest/binary>>) when C =:= $\t; C >= 32, C =/= 127, C =/= $\\ -> quoted(Rest);
quoted(_) -> false.

chunk_data(Buffer, Size, Recv, Emit, Bytes) when byte_size(Buffer) >= Size ->
    <<Data:Size/binary, Rest/binary>> = Buffer,
    case emit(Emit, Data) of
        ok -> chunk_end(Rest, Recv, Emit, Bytes + Size);
        {error, Reason} -> {error, Reason, Bytes}
    end;
chunk_data(Buffer, Size, Recv, Emit, Bytes) ->
    case emit(Emit, Buffer) of
        ok ->
            Got = byte_size(Buffer),
            refill(<<>>, Recv, Bytes + Got,
                   fun(B) -> chunk_data(B, Size - Got, Recv, Emit, Bytes + Got) end);
        {error, Reason} ->
            {error, Reason, Bytes}
    end.

chunk_end(<<"\r\n", Rest/binary>>, Recv, Emit, Bytes) ->
    copy_chunked(Rest, Recv, Emit, Bytes);
chunk_end(Buffer, Recv, Emit, Bytes) when Buffer =:= <<>>; Buffer =:= <<"\r">> ->
    refill(Buffer, Recv, Bytes, fun(B) -> chunk_end(B, Recv, Emit, Bytes) end);
chunk_end(_, _, _, Bytes) ->
    {error, bad_chunk, Bytes}.

%% The trailer section: lines ended by CRLF, without control characters or
%% folding, then an empty line.
trailers(<<"\r\n", Rest/binary>>, _, Bytes, _) ->
    {ok, Rest, Bytes};
trailers(_, _, Bytes, Seen) when Seen > 65536 ->
    {error, bad_chunk, Bytes};
trailers(Buffer, Recv, Bytes, Seen) ->
    case binary:match(Buffer, <<"\n">>) of
        nomatch when byte_size(Buffer) > 65536 ->
            {error, bad_chunk, Bytes};
        nomatch ->
            refill(Buffer, Recv, Bytes, fun(B) -> trailers(B, Recv, Bytes, Seen) end);
        {At, 1} when At > 1 ->
            Length = At - 1,
            case Buffer of
                <<C, _/binary>> when C =:= $\s; C =:= $\t ->
                    {error, bad_chunk, Bytes};
                <<Line:Length/binary, "\r\n", Rest/binary>> ->
                    case printable(Line) of
                        true -> trailers(Rest, Recv, Bytes, Seen + At + 1);
                        false -> {error, bad_chunk, Bytes}
                    end;
                _ ->
                    {error, bad_chunk, Bytes}
            end;
        _ ->
            {error, bad_chunk, Bytes}
    end.

refill(Buffer, Recv, Bytes, Next) ->
    case Recv() of
        {ok, Data} -> Next(<<Buffer/binary, Data/binary>>);
        {error, Reason} -> {error, Reason, Bytes}
    end.

emit(_, <<>>) -> ok;
emit({limit, _, Emit}, Data) -> Emit(Data);
emit(Emit, Data) -> Emit(Data).

chunk_emit(Emit) ->
    fun(Data) ->
        Emit([integer_to_binary(byte_size(Data), 16), <<"\r\n">>, Data, <<"\r\n">>])
    end.

%% Emit, for a chunked request body of at most Max bytes of payload (0: no
%% limit): its length is only known as it comes, so copy_chunked checks
%% each chunk's size against it.
body_limit(Emit, 0) -> Emit;
body_limit(Emit, Max) -> {limit, Max, Emit}.

%% The client's bytes, from the socket's messages. A request body must keep
%% coming: no more than the idle timeout between two packets (a client
%% sending a byte now and then would hold an upstream connection, and the
%% upstream's worker, for as long as it likes).
client_recv(#conn{socket = Socket, idle_timeout = Timeout}) ->
    fun Recv() ->
        receive
            {tcp, Socket, Data} ->
                {ok, Data};
            {tcp_passive, Socket} ->
                case inet:setopts(Socket, [{active, ?ACTIVE}]) of
                    ok -> Recv();
                    {error, _} -> {error, {client, closed}}
                end;
            {tcp_closed, Socket} ->
                {error, {client, closed}};
            {tcp_error, Socket, _} ->
                {error, {client, closed}}
        after Timeout ->
            {error, {client, timeout}}
        end
    end.

upstream_recv(Socket, #conn{upstream = #up{timeout = Timeout}}) ->
    fun() ->
        case up_recv(Socket, Timeout) of
            {ok, Data} -> {ok, Data};
            {error, timeout} -> {error, {upstream, timeout}};
            {error, _} -> {error, {upstream, closed}}
        end
    end.

upstream_emit(Socket) ->
    fun(Data) ->
        case up_send(Socket, Data) of
            ok -> ok;
            {error, timeout} -> {error, {upstream, timeout}};
            {error, Reason} -> {error, {upstream, Reason}}
        end
    end.

%% The upstream connection: the open one when the upstream has not closed
%% it, else a new one. {ok, Socket, Reused, Conn} | {error, Reason}
open(#conn{up = none, upstream = Up} = C) ->
    case connect(Up) of
        {ok, Socket} -> {ok, Socket, false, C#conn{up = Socket}};
        Error -> Error
    end;
open(#conn{up = Socket} = C) ->
    %% the armed socket got nothing: else a closed connection, or unexpected
    %% bytes, and it is not reusable
    case up_await(Socket, 0) of
        {error, timeout} -> {ok, Socket, true, C};
        _ -> open(close_upstream(C))
    end.

connect(#up{tls = Tls, address = Address, port = Port, timeout = Timeout} = Up) ->
    Tcp = [binary, {packet, raw}, {active, once}, {nodelay, true},
           {send_timeout, Timeout}, {send_timeout_close, true}],
    case Tls of
        false ->
            case gen_tcp:connect(Address, Port, Tcp, ?CONNECT_TIMEOUT) of
                {ok, Socket} -> {ok, {gen_tcp, Socket}};
                Error -> Error
            end;
        true ->
            case ssl:connect(Address, Port, Tcp ++ Up#up.tls_options, ?CONNECT_TIMEOUT) of
                {ok, Socket} -> {ok, {ssl, Socket}};
                Error -> Error
            end
    end.

close_upstream(#conn{up = none} = C) ->
    C;
close_upstream(#conn{up = Socket} = C) ->
    _ = up_close(Socket),
    flush_upstream(Socket),
    C#conn{up = none}.

%% The messages an armed socket sent before it was closed.
flush_upstream(Socket) ->
    case up_await(Socket, 0) of
        {error, timeout} -> ok;
        _ -> flush_upstream(Socket)
    end.

up_send({gen_tcp, S}, Data) -> gen_tcp:send(S, Data);
up_send({ssl, S}, Data) -> ssl:send(S, Data).

up_recv({gen_tcp, S}, Timeout) -> gen_tcp:recv(S, 0, Timeout);
up_recv({ssl, S}, Timeout) -> ssl:recv(S, 0, Timeout).

%% The message of an armed socket.
up_await({gen_tcp, S}, Timeout) ->
    receive
        {tcp, S, Data} -> {ok, Data};
        {tcp_closed, S} -> {error, closed};
        {tcp_error, S, Reason} -> {error, Reason}
    after Timeout -> {error, timeout}
    end;
up_await({ssl, S}, Timeout) ->
    receive
        {ssl, S, Data} -> {ok, Data};
        {ssl_closed, S} -> {error, closed};
        {ssl_error, S, Reason} -> {error, Reason}
    after Timeout -> {error, timeout}
    end.

up_setopts({gen_tcp, S}, Opts) -> inet:setopts(S, Opts);
up_setopts({ssl, S}, Opts) -> ssl:setopts(S, Opts).

up_close({gen_tcp, S}) -> gen_tcp:close(S);
up_close({ssl, S}) -> ssl:close(S).

%% The upstream settings of the Gleam `Upstream`, resolved once.
upstream_settings(none) ->
    none;
upstream_settings({some, {upstream, Tls, Host, Port, Timeout, Verify, MaxBody}}) ->
    Name = binary_to_list(Host),
    {Address, IsIp} = case inet:parse_address(Name) of
        {ok, Ip} -> {Ip, true};
        {error, _} -> {Name, false}
    end,
    Default = case Tls of true -> 443; false -> 80 end,
    Authority = case {Port, IsIp andalso tuple_size(Address) =:= 8} of
        {Default, false} -> Host;
        {Default, true} -> <<"[", Host/binary, "]">>;
        {_, false} -> <<Host/binary, ":", (integer_to_binary(Port))/binary>>;
        {_, true} -> <<"[", Host/binary, "]:", (integer_to_binary(Port))/binary>>
    end,
    Scheme = case Tls of true -> <<"https://">>; false -> <<"http://">> end,
    TlsOptions = case Tls of
        false ->
            [];
        true ->
            {ok, _} = application:ensure_all_started(ssl),
            Sni = case IsIp of
                true -> [];
                false -> [{server_name_indication, Name}]
            end,
            case Verify of
                true ->
                    [{verify, verify_peer}, {cacerts, public_key:cacerts_get()},
                     {customize_hostname_check,
                      [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}
                     | Sni];
                false ->
                    [{verify, verify_none} | Sni]
            end
    end,
    #up{tls = Tls, address = Address, port = Port, timeout = Timeout,
        max_body = MaxBody, authority = Authority, url = <<Scheme/binary, Authority/binary>>,
        tls_options = TlsOptions}.

trim(Bin) -> trim_end(skip_ows(Bin)).

trim_end(<<>>) -> <<>>;
trim_end(Bin) ->
    case binary:last(Bin) of
        C when C =:= $\s; C =:= $\t -> trim_end(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ -> Bin
    end.

%% The status line of a relayed response, with the upstream's reason phrase.
status_line(Status, Reason) ->
    [<<"HTTP/1.1 ">>, integer_to_binary(Status), $\s, Reason, <<"\r\n">>].
