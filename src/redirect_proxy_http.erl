%% The HTTP/1.1 server of the redirect listener.
%%
%% The redirect listener only answers small requests with small responses:
%% no TLS, no request bodies (they are never read: the connection is closed
%% after the response), no upgrades. This server does just that, with as
%% little work per request as possible:
%%
%% - a pool of acceptors; one process per connection, in passive mode, so a
%%   request costs one `recv` (whose timeout is the idle timeout: no timer)
%%   and one `send`
%% - the head parsed by `erlang:decode_packet`, headers kept as a list
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
-export([init/5]).

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
parse(Buffer) ->
    case erlang:decode_packet(http_bin, Buffer, []) of
        {ok, {http_request, Method, {abs_path, Target}, Version}, Rest} ->
            case headers(Rest, [], undefined, false, <<>>) of
                {ok, Headers, Host, Body, Connection, Rest1} ->
                    request(Method, Target, Version, Headers, Host, Body,
                            Connection, Rest1);
                Other ->
                    Other
            end;
        %% blank lines before a request line are ignored (RFC 9112 2.2)
        {ok, {http_error, <<"\r\n">>}, Rest} -> parse(Rest);
        {ok, {http_error, <<"\n">>}, Rest} -> parse(Rest);
        {ok, _, _} -> {error, 400};
        {more, _} -> more;
        {error, _} -> {error, 400}
    end.

%% Collects the headers (lowercase names, in order), the Host header, whether
%% the request has a body and the Connection header.
headers(Buffer, Acc, Host, Body, Connection) ->
    case erlang:decode_packet(httph_bin, Buffer, []) of
        {ok, {http_header, _, Field, Raw, Value}, Rest} ->
            case text(Value) of
                false ->
                    {error, 400};
                true ->
                    Name = name(Field, Raw),
                    Header = {Name, Value},
                    case Name of
                        <<"host">> when Host =:= undefined ->
                            headers(Rest, [Header | Acc], Value, Body, Connection);
                        <<"host">> ->
                            {error, 400};
                        <<"content-length">> ->
                            headers(Rest, [Header | Acc], Host,
                                    Body orelse string:trim(Value) =/= <<"0">>,
                                    Connection);
                        <<"transfer-encoding">> ->
                            headers(Rest, [Header | Acc], Host, true, Connection);
                        <<"connection">> ->
                            headers(Rest, [Header | Acc], Host, Body, Value);
                        _ ->
                            headers(Rest, [Header | Acc], Host, Body, Connection)
                    end
            end;
        {ok, http_eoh, Rest} ->
            {ok, lists:reverse(Acc), Host, Body, Connection, Rest};
        {ok, _, _} ->
            {error, 400};
        {more, _} ->
            more;
        {error, _} ->
            {error, 400}
    end.

request(_, _, Version, _, _, _, _, _) when Version =/= {1, 1}, Version =/= {1, 0} ->
    {error, 505};
request(_, _, {1, 1}, _, undefined, _, _, _) ->
    {error, 400};
request(Method0, Target, Version, Headers, Host0, Body, Connection, Rest) ->
    case {method(Method0), uri(Target)} of
        {{ok, Method}, true} ->
            Host = case Host0 of
                undefined -> <<>>;
                _ -> Host0
            end,
            {HostName, Port} = case binary:split(Host, <<":">>) of
                [Name, P] ->
                    {Name, try binary_to_integer(P) catch error:badarg -> 80 end};
                [Name] ->
                    {Name, 80}
            end,
            %% a fragment is not sent to servers: dropped if it is
            [Target1 | _] = binary:split(Target, <<"#">>),
            {Path, Query} = case binary:split(Target1, <<"?">>) of
                [P1, Q] -> {P1, {some, Q}};
                [P1] -> {P1, none}
            end,
            Request = {request, Method, Headers, nil, http, HostName,
                       {some, Port}, Path, Query},
            Close = Body orelse close_requested(Version, Connection),
            {ok, Request, Version, Close, Rest};
        _ ->
            {error, 400}
    end.

close_requested({1, 1}, <<>>) -> false;
close_requested({1, 1}, Connection) -> has_token(Connection, <<"close">>);
close_requested({1, 0}, Connection) -> not has_token(Connection, <<"keep-alive">>).

%% Whether a comma-separated header value has a token (case-insensitive).
has_token(Value, Token) when byte_size(Value) =:= byte_size(Token) ->
    lowercase(Value) =:= Token;
has_token(Value, Token) ->
    lists:any(fun(T) -> lowercase(string:trim(T)) =:= Token end,
              binary:split(Value, <<",">>, [global])).

%% Header names: the common ones `decode_packet` knows come as atoms.
name('Host', _) -> <<"host">>;
name('User-Agent', _) -> <<"user-agent">>;
name('Accept', _) -> <<"accept">>;
name('Accept-Encoding', _) -> <<"accept-encoding">>;
name('Accept-Language', _) -> <<"accept-language">>;
name('Connection', _) -> <<"connection">>;
name('Content-Length', _) -> <<"content-length">>;
name('Content-Type', _) -> <<"content-type">>;
name('Transfer-Encoding', _) -> <<"transfer-encoding">>;
name('Cache-Control', _) -> <<"cache-control">>;
name('Cookie', _) -> <<"cookie">>;
name('Referer', _) -> <<"referer">>;
name('Authorization', _) -> <<"authorization">>;
name('X-Forwarded-For', _) -> <<"x-forwarded-for">>;
name('Upgrade', _) -> <<"upgrade">>;
name('Via', _) -> <<"via">>;
name(_, Raw) -> lowercase(Raw).

method('GET') -> {ok, get};
method('HEAD') -> {ok, head};
method('POST') -> {ok, post};
method('PUT') -> {ok, put};
method('DELETE') -> {ok, delete};
method('OPTIONS') -> {ok, options};
method('TRACE') -> {ok, trace};
method(<<"PATCH">>) -> {ok, patch};
method(<<"CONNECT">>) -> {ok, connect};
method(Other) when is_binary(Other) ->
    case text(Other) of
        true -> {ok, {other, Other}};
        false -> error
    end;
method(_) -> error.

%% Valid UTF-8 without control characters other than tab.
text(<<C, Rest/binary>>) when C >= 32, C < 127; C =:= 9 -> text(Rest);
text(<<C/utf8, Rest/binary>>) when C >= 128 -> text(Rest);
text(<<>>) -> true;
text(_) -> false.

%% Only the characters of a URI (RFC 3986): a raw backslash, space, quote
%% or non-ASCII byte gets a 400, as `uri_string:parse` would reject it.
uri(<<C, Rest/binary>>) when ?URI_CHAR(C) -> uri(Rest);
uri(<<>>) -> true;
uri(_) -> false.

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
