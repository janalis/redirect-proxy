%% The HTTP/1.1 server of the redirect listener.
%%
%% The redirect listener only answers small requests with small responses:
%% no TLS, no request bodies (they are never read: the connection is closed
%% after the response), no upgrades. This server does just that, with as
%% little work per request as possible:
%%
%% - a pool of acceptors; one process per connection, its socket in
%%   `{active, N}` mode, so a request costs one message (the receive timeout
%%   is the idle timeout: no timer) and one `send`
%% - the head parsed in one pass (`parse/1`), headers kept as a list
%% - the Gleam handler called with a `gleam/http` request whose body is the
%%   client address (`Result(mist.IpAddress, Nil)`, looked up once per
%%   connection and only when the access log needs it), and returning a
%%   response whose body is a bytes tree (iodata)
%% - `content-length` and `date` (rendered once a second per connection)
%%   added, and the response sent as one iolist
%%
%% Pipelined requests are answered in order. The connection is closed after
%% a response that says `connection: close` (draining), after a request with
%% a body, after an HTTP/1.0 request without `connection: keep-alive`, after
%% a 1.1 request with `connection: close`, and on any malformed request.
-module(redirect_proxy_http).

-export([start/4]).
%% internal
-export([init/5, parse/1]).

%% unreserved, sub-delims, ":", "@", "/", "?", "%" and "#" (RFC 3986)
-define(URI_CHAR(C),
    ((C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z)
     orelse (C >= $0 andalso C =< $9)
     orelse C =:= $/ orelse C =:= $- orelse C =:= $. orelse C =:= $_
     orelse C =:= $~ orelse C =:= $% orelse C =:= $? orelse C =:= $=
     orelse C =:= $& orelse C =:= $+ orelse C =:= $, orelse C =:= $;
     orelse C =:= $: orelse C =:= $@ orelse C =:= $! orelse C =:= $$
     orelse C =:= $' orelse C =:= $( orelse C =:= $) orelse C =:= $*
     orelse C =:= $#)).

%% token characters of methods and header names (RFC 9110 5.6.2)
-define(TCHAR(C),
    ((C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z)
     orelse (C >= $0 andalso C =< $9)
     orelse C =:= $- orelse C =:= $_ orelse C =:= $. orelse C =:= $!
     orelse C =:= $# orelse C =:= $$ orelse C =:= $% orelse C =:= $&
     orelse C =:= $' orelse C =:= $* orelse C =:= $+ orelse C =:= $^
     orelse C =:= $` orelse C =:= $| orelse C =:= $~)).

%% packets delivered as messages before the socket must be re-armed
-define(ACTIVE, 64).

-record(conn, {
    socket,
    handler,
    peer,
    idle_timeout,
    max_head,
    %% {Second, Rendered} of the last `date` header
    date = {0, <<>>}
}).

%% Opts: the Gleam `Options(idle_timeout_ms, max_head_bytes, peer)`.
%% Returns the `actor.Started(Int)` (the bound port) of a gleam_otp child, or
%% an `actor.StartError`.
start(Address, Port, Handler, Opts) ->
    case proc_lib:start_link(?MODULE, init, [self(), Address, Port, Handler, Opts]) of
        {ok, Pid, Bound} -> {ok, {started, Pid, Bound}};
        {error, Reason} -> {error, {init_failed, describe(Reason)}}
    end.

describe({invalid_address, Address}) ->
    <<"invalid listen address: ", Address/binary>>;
describe(Reason) ->
    iolist_to_binary(io_lib:format("cannot listen: ~0p", [Reason])).

%% ---------------------------------------------------------------------------
%% Listener: owns the listening socket and the acceptors
%% ---------------------------------------------------------------------------

init(Parent, Address, Port, Handler, Opts) ->
    process_flag(trap_exit, true),
    Listened = case ip(Address) of
        {ok, Ip} ->
            gen_tcp:listen(Port, [
                binary, {packet, raw}, {active, false}, {ip, Ip},
                {reuseaddr, true}, {nodelay, true}, {backlog, 1024},
                {send_timeout, 30000}, {send_timeout_close, true}
            ]);
        Error ->
            Error
    end,
    case Listened of
        {ok, Listen} ->
            {ok, Bound} = inet:port(Listen),
            Count = max(4, erlang:system_info(schedulers_online)),
            [spawn_acceptor(Listen, Handler, Opts) || _ <- lists:seq(1, Count)],
            proc_lib:init_ack(Parent, {ok, self(), Bound}),
            listener_loop(Parent, Listen, Handler, Opts);
        {error, Reason} ->
            proc_lib:init_ack(Parent, {error, Reason}),
            exit(normal)
    end.

ip(<<"0.0.0.0">>) -> {ok, {0, 0, 0, 0}};
ip(<<"localhost">>) -> {ok, {127, 0, 0, 1}};
ip(Address) ->
    case inet:parse_address(binary_to_list(Address)) of
        {ok, Ip} -> {ok, Ip};
        {error, _} -> {error, {invalid_address, Address}}
    end.

listener_loop(Parent, Listen, Handler, Opts) ->
    receive
        {'EXIT', Parent, Reason} ->
            gen_tcp:close(Listen),
            exit(Reason);
        {'EXIT', _Acceptor, normal} ->
            listener_loop(Parent, Listen, Handler, Opts);
        {'EXIT', _Acceptor, Reason} ->
            logger:error(iolist_to_binary(io_lib:format(
                "redirect listener acceptor stopped: ~0p", [Reason]))),
            spawn_acceptor(Listen, Handler, Opts),
            listener_loop(Parent, Listen, Handler, Opts);
        _ ->
            listener_loop(Parent, Listen, Handler, Opts)
    end.

spawn_acceptor(Listen, Handler, Opts) ->
    spawn_link(fun() -> accept(Listen, Handler, Opts) end).

accept(Listen, Handler, Opts) ->
    case gen_tcp:accept(Listen) of
        {ok, Socket} ->
            Pid = spawn(fun() ->
                receive
                    {go, S} -> connection(S, Handler, Opts)
                after 5000 ->
                    exit(normal)
                end
            end),
            case gen_tcp:controlling_process(Socket, Pid) of
                ok -> Pid ! {go, Socket};
                {error, _} -> gen_tcp:close(Socket), exit(Pid, kill)
            end,
            accept(Listen, Handler, Opts);
        {error, closed} ->
            ok;
        {error, Reason} when Reason =:= emfile; Reason =:= enfile ->
            logger:warning(iolist_to_binary(io_lib:format(
                "redirect listener cannot accept connections: ~p", [Reason]))),
            timer:sleep(100),
            accept(Listen, Handler, Opts);
        {error, _} ->
            accept(Listen, Handler, Opts)
    end.

%% ---------------------------------------------------------------------------
%% Connection
%% ---------------------------------------------------------------------------

connection(Socket, Handler, {options, IdleTimeout, MaxHead, WithPeer}) ->
    Peer = case WithPeer of
        true -> peer(Socket);
        false -> {error, nil}
    end,
    ok = inet:setopts(Socket, [{active, ?ACTIVE}]),
    request(<<>>, #conn{
        socket = Socket,
        handler = Handler,
        peer = Peer,
        idle_timeout = IdleTimeout,
        max_head = MaxHead
    }).

peer(Socket) ->
    case inet:peername(Socket) of
        {ok, {{A, B, C, D}, _}} -> {ok, {ip_v4, A, B, C, D}};
        {ok, {{A, B, C, D, E, F, G, H}, _}} -> {ok, {ip_v6, A, B, C, D, E, F, G, H}};
        _ -> {error, nil}
    end.

%% Waits for more bytes of a request head, then parses it again. The socket
%% delivers up to ?ACTIVE packets as messages before it must be re-armed:
%% no call to the port per request, and a bounded mailbox.
more(Buffer, #conn{socket = Socket, idle_timeout = Timeout} = C) ->
    receive
        {tcp, Socket, Data} ->
            request(<<Buffer/binary, Data/binary>>, C);
        {tcp_passive, Socket} ->
            case inet:setopts(Socket, [{active, ?ACTIVE}]) of
                ok -> more(Buffer, C);
                {error, _} -> close(C)
            end;
        {tcp_closed, Socket} ->
            close(C);
        {tcp_error, Socket, _} ->
            close(C)
    after Timeout ->
        close(C)
    end.

request(<<>>, C) ->
    more(<<>>, C);
request(Buffer, #conn{max_head = Max} = C) ->
    case parse(Buffer) of
        {ok, Request, Version, Close, Rest} ->
            respond(Request, Version, Close, Rest, C);
        more when byte_size(Buffer) >= Max ->
            %% 414 while the request line itself is incomplete
            Status = case binary:match(Buffer, <<"\n">>) of
                nomatch -> 414;
                _ -> 431
            end,
            reject(Status, C);
        more ->
            more(Buffer, C);
        {error, Status} ->
            reject(Status, C)
    end.

%% {ok, Request, Version, Close, Rest} | more | {error, Status}
%%
%% One pass over the head, without `erlang:decode_packet` (whose header
%% lines cost several times the rest of the parse): the request line, then
%% each header line, the bytes checked as they are read.
%% blank lines before a request line are ignored (RFC 9112 2.2)
parse(<<"\r\n", Rest/binary>>) -> parse(Rest);
parse(<<"\n", Rest/binary>>) -> parse(Rest);
parse(<<"\r">>) -> more;
parse(Buffer) -> method(Buffer).

%% The method: the common ones matched whole, any other token kept as is.
method(<<"GET ", Rest/binary>>) -> target(Rest, get);
method(<<"HEAD ", Rest/binary>>) -> target(Rest, head);
method(<<"POST ", Rest/binary>>) -> target(Rest, post);
method(<<"PUT ", Rest/binary>>) -> target(Rest, put);
method(<<"DELETE ", Rest/binary>>) -> target(Rest, delete);
method(<<"OPTIONS ", Rest/binary>>) -> target(Rest, options);
method(<<"PATCH ", Rest/binary>>) -> target(Rest, patch);
method(Buffer) ->
    case token(Buffer, 0) of
        {Length, $\s} when Length > 0 ->
            <<Method:Length/binary, $\s, Rest/binary>> = Buffer,
            target(Rest, other_method(Method));
        {_, more} -> more;
        _ -> {error, 400}
    end.

other_method(<<"TRACE">>) -> trace;
other_method(<<"CONNECT">>) -> connect;
other_method(Method) -> {other, Method}.

%% The length of the token at the start of Bin, and the byte after it
%% (`more` when Bin ends first).
token(Bin, N) ->
    case Bin of
        <<_:N/binary, C, _/binary>> when ?TCHAR(C) -> token(Bin, N + 1);
        <<_:N/binary, C, _/binary>> -> {N, C};
        _ -> {N, more}
    end.

%% An absolute path, with only the characters of a URI (RFC 3986): a raw
%% backslash, space, quote or non-ASCII byte gets a 400, as
%% `uri_string:parse` would reject it. The positions of the first `?` and
%% `#` are noted on the way.
target(<<$/, _/binary>> = Bin, Method) -> target(Bin, Method, 1, none, none);
target(<<>>, _) -> more;
target(_, _) -> {error, 400}.

target(Bin, Method, N, Query, Fragment) ->
    case Bin of
        <<_:N/binary, $\s, _/binary>> ->
            <<Target:N/binary, $\s, Rest/binary>> = Bin,
            version(Rest, Method, Target, Query, Fragment);
        <<_:N/binary, $?, _/binary>> when Query =:= none, Fragment =:= none ->
            target(Bin, Method, N + 1, N, Fragment);
        <<_:N/binary, $#, _/binary>> when Fragment =:= none ->
            target(Bin, Method, N + 1, Query, N);
        <<_:N/binary, C, _/binary>> when ?URI_CHAR(C) ->
            target(Bin, Method, N + 1, Query, Fragment);
        <<_:N/binary, _, _/binary>> ->
            {error, 400};
        _ ->
            more
    end.

version(<<"HTTP/1.1\r\n", Rest/binary>>, M, T, Q, F) -> headers(Rest, M, T, Q, F, {1, 1});
version(<<"HTTP/1.0\r\n", Rest/binary>>, M, T, Q, F) -> headers(Rest, M, T, Q, F, {1, 0});
version(<<"HTTP/1.1\n", Rest/binary>>, M, T, Q, F) -> headers(Rest, M, T, Q, F, {1, 1});
version(<<"HTTP/1.0\n", Rest/binary>>, M, T, Q, F) -> headers(Rest, M, T, Q, F, {1, 0});
version(<<"HTTP/1.", Minor, "\r">>, _, _, _, _) when Minor =:= $0; Minor =:= $1 ->
    more;
version(<<"HTTP/1.", Minor, "\r", _/binary>>, _, _, _, _) when Minor =:= $0; Minor =:= $1 ->
    {error, 400};
version(<<"HTTP/", Major, $., Minor, End, _/binary>>, _, _, _, _)
  when Major >= $0, Major =< $9, Minor >= $0, Minor =< $9,
       End =:= $\r orelse End =:= $\n ->
    {error, 505};
version(Bin, _, _, _, _) when byte_size(Bin) < 10 ->
    case binary:match(Bin, <<"\n">>) of
        nomatch -> more;
        _ -> {error, 400}
    end;
version(_, _, _, _, _) ->
    {error, 400}.

headers(Bin, Method, Target, Query, Fragment, Version) ->
    case headers(Bin, [], undefined, false, <<>>) of
        {ok, Headers, Host, Body, Connection, Rest} ->
            request(Method, Target, Query, Fragment, Version, Headers, Host,
                    Body, Connection, Rest);
        Other ->
            Other
    end.

%% Collects the headers (lowercase names, in order), the Host header, whether
%% the request has a body and the Connection header.
headers(<<"\r\n", Rest/binary>>, Acc, Host, Body, Connection) ->
    {ok, lists:reverse(Acc), Host, Body, Connection, Rest};
headers(<<"\n", Rest/binary>>, Acc, Host, Body, Connection) ->
    {ok, lists:reverse(Acc), Host, Body, Connection, Rest};
headers(<<>>, _, _, _, _) ->
    more;
headers(<<"\r">>, _, _, _, _) ->
    more;
headers(Bin, Acc, Host, Body, Connection) ->
    case header(Bin) of
        {Name, Value, Rest} ->
            Header = {Name, Value},
            case Name of
                <<"host">> when Host =:= undefined ->
                    headers(Rest, [Header | Acc], Value, Body, Connection);
                <<"host">> ->
                    {error, 400};
                <<"content-length">> ->
                    headers(Rest, [Header | Acc], Host,
                            Body orelse Value =/= <<"0">>, Connection);
                <<"transfer-encoding">> ->
                    headers(Rest, [Header | Acc], Host, true, Connection);
                <<"connection">> ->
                    headers(Rest, [Header | Acc], Host, Body, Value);
                _ ->
                    headers(Rest, [Header | Acc], Host, Body, Connection)
            end;
        Other ->
            Other
    end.

%% One header line: {LowercaseName, Value, Rest} | more | {error, 400}.
%% A line starting with whitespace (obsolete line folding), a name that is
%% not a token or is followed by whitespace, and control characters in the
%% value are errors.
header(Bin) ->
    case name(Bin, 0, false) of
        {Length, Upper} when Length > 0 ->
            <<Raw:Length/binary, $:, Rest/binary>> = Bin,
            Name = case Upper of
                true -> lowercase_name(Raw);
                false -> Raw
            end,
            value(skip_ows(Rest), Name);
        more ->
            more;
        _ ->
            {error, 400}
    end.

%% The length of a header name ended by `:`, and whether it has upper case
%% letters.
name(Bin, N, Upper) ->
    case Bin of
        <<_:N/binary, C, _/binary>> when C >= $a, C =< $z; C =:= $- ->
            name(Bin, N + 1, Upper);
        <<_:N/binary, C, _/binary>> when C >= $A, C =< $Z ->
            name(Bin, N + 1, true);
        <<_:N/binary, $:, _/binary>> ->
            {N, Upper};
        <<_:N/binary, C, _/binary>> when ?TCHAR(C) ->
            name(Bin, N + 1, Upper);
        <<_:N/binary, _, _/binary>> ->
            error;
        _ ->
            more
    end.

%% The names browsers and proxies send capitalised, without building a new
%% binary byte by byte.
lowercase_name(<<"Host">>) -> <<"host">>;
lowercase_name(<<"User-Agent">>) -> <<"user-agent">>;
lowercase_name(<<"Accept">>) -> <<"accept">>;
lowercase_name(<<"Accept-Encoding">>) -> <<"accept-encoding">>;
lowercase_name(<<"Accept-Language">>) -> <<"accept-language">>;
lowercase_name(<<"Connection">>) -> <<"connection">>;
lowercase_name(<<"Content-Length">>) -> <<"content-length">>;
lowercase_name(<<"Content-Type">>) -> <<"content-type">>;
lowercase_name(<<"Transfer-Encoding">>) -> <<"transfer-encoding">>;
lowercase_name(<<"Cache-Control">>) -> <<"cache-control">>;
lowercase_name(<<"Cookie">>) -> <<"cookie">>;
lowercase_name(<<"Referer">>) -> <<"referer">>;
lowercase_name(<<"Authorization">>) -> <<"authorization">>;
lowercase_name(<<"Upgrade-Insecure-Requests">>) -> <<"upgrade-insecure-requests">>;
lowercase_name(<<"Sec-Fetch-Dest">>) -> <<"sec-fetch-dest">>;
lowercase_name(<<"Sec-Fetch-Mode">>) -> <<"sec-fetch-mode">>;
lowercase_name(<<"Sec-Fetch-Site">>) -> <<"sec-fetch-site">>;
lowercase_name(<<"Sec-Fetch-User">>) -> <<"sec-fetch-user">>;
lowercase_name(<<"X-Forwarded-For">>) -> <<"x-forwarded-for">>;
lowercase_name(<<"X-Forwarded-Proto">>) -> <<"x-forwarded-proto">>;
lowercase_name(<<"X-Real-IP">>) -> <<"x-real-ip">>;
lowercase_name(<<"Via">>) -> <<"via">>;
lowercase_name(Name) -> lowercase(Name).

skip_ows(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t -> skip_ows(Rest);
skip_ows(Bin) -> Bin.

%% The value up to the end of the line, without trailing whitespace: valid
%% UTF-8 without control characters other than tab.
value(Bin, Name) -> value(Bin, Name, 0, 0).

%% End: the length without trailing whitespace.
value(Bin, Name, N, End) ->
    case Bin of
        <<_:N/binary, C, _/binary>> when C > 32, C < 127 ->
            value(Bin, Name, N + 1, N + 1);
        <<_:N/binary, C, _/binary>> when C =:= $\s; C =:= $\t ->
            value(Bin, Name, N + 1, End);
        <<_:N/binary, "\r\n", Rest/binary>> ->
            <<Value:End/binary, _/binary>> = Bin,
            {Name, Value, Rest};
        <<_:N/binary, "\n", Rest/binary>> ->
            <<Value:End/binary, _/binary>> = Bin,
            {Name, Value, Rest};
        <<_:N/binary, C/utf8, _/binary>> when C >= 128 ->
            Next = N + utf8_size(C),
            value(Bin, Name, Next, Next);
        <<_:N/binary, "\r">> ->
            more;
        <<_:N/binary, C, _/binary>> when C >= 128 ->
            %% the rest of a UTF-8 sequence may still come
            <<_:N/binary, Tail/binary>> = Bin,
            case partial_utf8(Tail) of
                true -> more;
                false -> {error, 400}
            end;
        <<_:N/binary, _, _/binary>> ->
            {error, 400};
        _ ->
            more
    end.

%% Whether Bin is the start of a UTF-8 sequence that is not complete yet: a
%% lead byte, then fewer continuation bytes than it announces.
partial_utf8(<<Lead, Rest/binary>>) when Lead >= 16#C2, Lead =< 16#F4 ->
    Size = if Lead < 16#E0 -> 2; Lead < 16#F0 -> 3; true -> 4 end,
    byte_size(Rest) < Size - 1
        andalso lists:all(fun(C) -> C band 16#C0 =:= 16#80 end, binary_to_list(Rest));
partial_utf8(_) ->
    false.

utf8_size(C) when C < 16#800 -> 2;
utf8_size(C) when C < 16#10000 -> 3;
utf8_size(_) -> 4.

request(_, _, _, _, {1, 1}, _, undefined, _, _, _) ->
    {error, 400};
request(Method, Target0, Query0, Fragment, Version, Headers, Host0, Body,
        Connection, Rest) ->
    Host = case Host0 of
        undefined -> <<>>;
        _ -> Host0
    end,
    {HostName, Port} = case binary:match(Host, <<":">>) of
        {At, 1} ->
            <<Name:At/binary, $:, P/binary>> = Host,
            {Name, try binary_to_integer(P) catch error:badarg -> 80 end};
        nomatch ->
            {Host, 80}
    end,
    %% a fragment is not sent to servers: dropped if it is
    Target = case Fragment of
        none -> Target0;
        _ -> binary:part(Target0, 0, Fragment)
    end,
    {Path, Query} = case Query0 of
        none ->
            {Target, none};
        _ ->
            <<P1:Query0/binary, $?, Q/binary>> = Target,
            {P1, {some, Q}}
    end,
    Request = {request, Method, Headers, nil, http, HostName,
               {some, Port}, Path, Query},
    Close = Body orelse close_requested(Version, Connection),
    {ok, Request, Version, Close, Rest}.

close_requested({1, 1}, <<>>) -> false;
close_requested({1, 1}, Connection) -> has_token(Connection, <<"close">>);
close_requested({1, 0}, Connection) -> not has_token(Connection, <<"keep-alive">>).

%% Whether a comma-separated header value has a token (case-insensitive;
%% Token is lower case). Browsers send `connection: keep-alive` with every
%% request: no allocation, and no `string:trim` (which costs microseconds).
has_token(<<C, Rest/binary>>, Token) when C =:= $\s; C =:= $\t; C =:= $, ->
    has_token(Rest, Token);
has_token(<<>>, _) ->
    false;
has_token(Value, Token) ->
    case same_token(Value, Token) of
        true -> true;
        false -> has_token(next_item(Value), Token)
    end.

%% Whether Value starts with Token (case-insensitive), followed by the end
%% of the value or of the list item.
same_token(<<C, Rest/binary>>, <<T, Token/binary>>) when C =:= T; C + 32 =:= T, C >= $A, C =< $Z ->
    same_token(Rest, Token);
same_token(Rest, <<>>) ->
    item_end(Rest);
same_token(_, _) ->
    false.

item_end(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t -> item_end(Rest);
item_end(<<$,, _/binary>>) -> true;
item_end(<<>>) -> true;
item_end(_) -> false.

next_item(<<$,, Rest/binary>>) -> Rest;
next_item(<<_, Rest/binary>>) -> next_item(Rest);
next_item(<<>>) -> <<>>.

lowercase(Bin) -> << <<(lower(C))>> || <<C>> <= Bin >>.

lower(C) when C >= $A, C =< $Z -> C + 32;
lower(C) -> C.

%% ---------------------------------------------------------------------------
%% Responses
%% ---------------------------------------------------------------------------

respond(Request0, Version, Close0, Rest,
        #conn{handler = Handler, peer = Peer} = C) ->
    Request = setelement(4, Request0, Peer),
    Head = element(2, Request) =:= head,
    case call(Handler, Request) of
        {ok, {response, Status, Headers, Body}} ->
            Close = Close0 orelse lists:member({<<"connection">>, <<"close">>}, Headers),
            {Date, C1} = date(C),
            Connection = case {Close, Version} of
                {true, _} -> <<"connection: close\r\n">>;
                {false, {1, 0}} -> <<"connection: keep-alive\r\n">>;
                {false, _} -> <<>>
            end,
            Length = case Status of
                S when S < 200; S =:= 204; S =:= 304 -> <<>>;
                _ -> [<<"content-length: ">>, integer_to_binary(iolist_size(Body)), <<"\r\n">>]
            end,
            Response = [status_line(Status), encode_headers(Headers), Length,
                        <<"date: ">>, Date, <<"\r\n">>, Connection, <<"\r\n">>
                        | case Head of
                              true -> [];
                              false -> Body
                          end],
            case gen_tcp:send(C1#conn.socket, Response) of
                ok when Close -> close(C1);
                ok -> request(Rest, C1);
                {error, _} -> close(C1)
            end;
        error ->
            reject(500, C)
    end.

call(Handler, Request) ->
    try
        {ok, Handler(Request)}
    catch
        Class:Reason:Stack ->
            logger:error(iolist_to_binary(io_lib:format(
                "redirect listener handler failed: ~0p: ~0p~n~0p",
                [Class, Reason, Stack]))),
            error
    end.

%% An empty response, then the connection is closed.
reject(Status, C) ->
    {Date, C1} = date(C),
    _ = gen_tcp:send(C1#conn.socket, [
        status_line(Status),
        <<"content-length: 0\r\ndate: ">>, Date,
        <<"\r\ncache-control: no-store\r\nconnection: close\r\n\r\n">>
    ]),
    close(C1).

close(#conn{socket = Socket}) ->
    gen_tcp:close(Socket),
    exit(normal).

%% The connection header is the server's to set.
encode_headers([{<<"connection">>, _} | Rest]) ->
    encode_headers(Rest);
encode_headers([{Name, Value} | Rest]) ->
    [Name, <<": ">>, Value, <<"\r\n">> | encode_headers(Rest)];
encode_headers([]) ->
    [].

date(#conn{date = {Second, Rendered}} = C) ->
    case erlang:system_time(second) of
        Second ->
            {Rendered, C};
        Now ->
            Date = http_date(Now),
            {Date, C#conn{date = {Now, Date}}}
    end.

http_date(Seconds) ->
    {{Y, Mo, D} = Day, {H, Mi, S}} =
        calendar:system_time_to_universal_time(Seconds, second),
    iolist_to_binary([
        weekday(calendar:day_of_the_week(Day)), <<", ">>, two(D), <<" ">>,
        month(Mo), <<" ">>, integer_to_binary(Y), <<" ">>,
        two(H), <<":">>, two(Mi), <<":">>, two(S), <<" GMT">>
    ]).

two(N) when N < 10 -> [$0, $0 + N];
two(N) -> integer_to_binary(N).

weekday(1) -> <<"Mon">>; weekday(2) -> <<"Tue">>; weekday(3) -> <<"Wed">>;
weekday(4) -> <<"Thu">>; weekday(5) -> <<"Fri">>; weekday(6) -> <<"Sat">>;
weekday(7) -> <<"Sun">>.

month(1) -> <<"Jan">>; month(2) -> <<"Feb">>; month(3) -> <<"Mar">>;
month(4) -> <<"Apr">>; month(5) -> <<"May">>; month(6) -> <<"Jun">>;
month(7) -> <<"Jul">>; month(8) -> <<"Aug">>; month(9) -> <<"Sep">>;
month(10) -> <<"Oct">>; month(11) -> <<"Nov">>; month(12) -> <<"Dec">>.

status_line(200) -> <<"HTTP/1.1 200 OK\r\n">>;
status_line(204) -> <<"HTTP/1.1 204 No Content\r\n">>;
status_line(301) -> <<"HTTP/1.1 301 Moved Permanently\r\n">>;
status_line(302) -> <<"HTTP/1.1 302 Found\r\n">>;
status_line(303) -> <<"HTTP/1.1 303 See Other\r\n">>;
status_line(307) -> <<"HTTP/1.1 307 Temporary Redirect\r\n">>;
status_line(308) -> <<"HTTP/1.1 308 Permanent Redirect\r\n">>;
status_line(400) -> <<"HTTP/1.1 400 Bad Request\r\n">>;
status_line(401) -> <<"HTTP/1.1 401 Unauthorized\r\n">>;
status_line(404) -> <<"HTTP/1.1 404 Not Found\r\n">>;
status_line(405) -> <<"HTTP/1.1 405 Method Not Allowed\r\n">>;
status_line(410) -> <<"HTTP/1.1 410 Gone\r\n">>;
status_line(414) -> <<"HTTP/1.1 414 URI Too Long\r\n">>;
status_line(431) -> <<"HTTP/1.1 431 Request Header Fields Too Large\r\n">>;
status_line(451) -> <<"HTTP/1.1 451 Unavailable For Legal Reasons\r\n">>;
status_line(500) -> <<"HTTP/1.1 500 Internal Server Error\r\n">>;
status_line(503) -> <<"HTTP/1.1 503 Service Unavailable\r\n">>;
status_line(505) -> <<"HTTP/1.1 505 HTTP Version Not Supported\r\n">>;
status_line(Status) ->
    [<<"HTTP/1.1 ">>, integer_to_binary(Status), <<" ">>,
     reason(Status div 100), <<"\r\n">>].

reason(1) -> <<"Informational">>;
reason(2) -> <<"Success">>;
reason(3) -> <<"Redirection">>;
reason(4) -> <<"Client Error">>;
reason(_) -> <<"Server Error">>.
