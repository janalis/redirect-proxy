%% The HTTP/1.1 server of the redirect listener.
%%
%% The redirect listener answers small requests with small responses: no
%% TLS, no request bodies (they are never read: the connection is closed
%% after the response), no upgrades. This server does just that, with as
%% little work per request as possible:
%%
%% - a pool of acceptors, up to a number of open connections, and of ports
%%   in the VM (90 % of its port limit: a connection over it is closed at
%%   once, rather than the VM running out of ports); one process per connection, its socket in
%%   `{active, N}` mode, so a request costs one message (the receive timeout
%%   is the idle timeout: no timer) and one `send`
%% - the head parsed in one pass (`parse/1`), headers kept as a list
%% - the Gleam handler called with a `gleam/http` request whose body is the
%%   client address (`Result(mist.IpAddress, Nil)`, looked up once per
%%   connection and only when the access log needs it), and returning a
%%   response whose body is a bytes tree (iodata)
%% - `content-length` and `date` (rendered once a second per connection)
%%   added, and the response sent as one iolist, without waiting for the
%%   driver's reply (`send/2`)
%%
%% Pipelined requests are answered in order. The connection is closed after
%% a response that says `connection: close` (draining), after a request with
%% a body, after an HTTP/1.0 request without `connection: keep-alive`, after
%% a 1.1 request with `connection: close`, and on any malformed request. A
%% request head must be complete within the idle timeout of its first
%% bytes, however they trickle in: a 408 after that.
%%
%% With an upstream (`server.upstream`), the handler can leave a request to
%% it instead of answering (`Forward`): see "Forwarding to the upstream".
%% The body of a forwarded request is read and forwarded, and the connection
%% kept alive after it when its framing was unambiguous.
-module(redirect_proxy_http).

-export([start/4, drain/0]).
%% internal
-export([init/5, parse/1, idle/4]).

%% unreserved, sub-delims, ":", "@", "/", "?", "%" and "#" (RFC 3986), and
%% the printable characters browsers send unescaped in queries although
%% RFC 3986 does not allow them there: "[", "]", "{", "}", "|", "^" and "`"
%% (`?a[]=1` is common)
-define(URI_CHAR(C),
    ((C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z)
     orelse (C >= $0 andalso C =< $9)
     orelse C =:= $/ orelse C =:= $- orelse C =:= $. orelse C =:= $_
     orelse C =:= $~ orelse C =:= $% orelse C =:= $? orelse C =:= $=
     orelse C =:= $& orelse C =:= $+ orelse C =:= $, orelse C =:= $;
     orelse C =:= $: orelse C =:= $@ orelse C =:= $! orelse C =:= $$
     orelse C =:= $' orelse C =:= $( orelse C =:= $) orelse C =:= $*
     orelse C =:= $# orelse C =:= $[ orelse C =:= $] orelse C =:= ${
     orelse C =:= $} orelse C =:= $| orelse C =:= $^ orelse C =:= $`)).

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
%% lingering close (linger_close/1): for at most 2 s, 500 ms without a
%% byte, 1 MiB
-define(LINGER_MS, 2000).
-define(LINGER_IDLE_MS, 500).
-define(LINGER_BYTES, 1048576).

%% The minimum heap of a connection process, in words (20 KiB): a request
%% leaves 1 to 2 KiB of garbage, so the default heap (233 words) is
%% collected after almost every request. A connection without a request
%% for `hibernate_after/1` hibernates, which shrinks its heap to what it
%% still holds (a few hundred bytes), until the next one.
-define(CONN_HEAP, 2584).

%% The caller tag of `send/2`: two bytes of length, then the external term
%% format of the atom `sent` (`term_to_binary(sent)`), which inet_drv puts in
%% its reply, `{inet_reply, Socket, Status, sent}`.
-define(SEND_TAG, <<0, 7, 131, 119, 4, "sent">>).

-record(conn, {
    socket,
    handler,
    peer,
    idle_timeout,
    max_head,
    %% none | the monotonic time (ms) by which the request head being read
    %% must be complete: bytes trickled in do not extend it
    deadline = none,
    %% {Second, Rendered} of the last `date` header
    date = {0, <<>>},
    %% none | #up{}: where unanswered requests are forwarded
    upstream = none,
    %% none | {gen_tcp | ssl, Socket}: the open upstream connection
    up = none
}).

%% The upstream, resolved when the listener starts.
-record(up, {
    tls,
    %% an IP tuple, or a host name to resolve on each connect
    address,
    port,
    timeout,
    %% `host[:port]`, sent when the client sent no Host
    authority,
    %% for the log
    url,
    tls_options
}).

%% atomics: the second of the last warning about the upstream
%% (?UPSTREAM_LOG), and about the listener (?LISTENER_LOG)
-define(WARNED, {?MODULE, warned}).
-define(UPSTREAM_LOG, 1).
-define(LISTENER_LOG, 2).

%% The pg scope, and group, of the redirect listeners (`drain/0`).
-define(SCOPE, redirect_proxy_listeners).

%% Opts: the Gleam `Options(idle_timeout_ms, max_head_bytes, peer, upstream)`;
%% tests can add the connection cap (`{options, ..., MaxConnections}`).
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

init(Parent, Address, Port, Handler, {options, Idle, MaxHead, Peer, Upstream}) ->
    Cap = max(1, port_cap()),
    init(Parent, Address, Port, Handler, {options, Idle, MaxHead, Peer, Upstream, Cap});
init(Parent, Address, Port, Handler, {options, Idle, MaxHead, Peer, Upstream, Cap}) ->
    process_flag(trap_exit, true),
    case persistent_term:get(?WARNED, undefined) of
        undefined -> persistent_term:put(?WARNED, atomics:new(2, []));
        _ -> ok
    end,
    Opts = {options, Idle, MaxHead, Peer, upstream_settings(Upstream)},
    %% the open connections, and their cap
    Limit = {self(), atomics:new(1, []), Cap},
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
            [spawn_acceptor(Listen, Handler, Opts, Limit) || _ <- lists:seq(1, Count)],
            join_listeners(),
            proc_lib:init_ack(Parent, {ok, self(), Bound}),
            listener_loop(Parent, Listen, Handler, Opts, Limit, #{});
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

%% The listener also counts the open connections: it monitors each one (the
%% acceptors are busy accepting), and its count goes down when one ends,
%% whatever the way (a monitor is not lost in hibernation, as a `try` is).
%% It keeps their pids (Conns) to tell them when the node drains (`drain/0`).
listener_loop(Parent, Listen, Handler, Opts, {_, Count, _} = Limit, Conns) ->
    receive
        {connection, Pid} ->
            _ = erlang:monitor(process, Pid),
            listener_loop(Parent, Listen, Handler, Opts, Limit, Conns#{Pid => []});
        {'DOWN', _, process, Pid, _} ->
            atomics:sub(Count, 1, 1),
            listener_loop(Parent, Listen, Handler, Opts, Limit, maps:remove(Pid, Conns));
        drain ->
            maps:foreach(fun(Pid, _) -> Pid ! drain end, Conns),
            listener_loop(Parent, Listen, Handler, Opts, Limit, Conns);
        {'EXIT', Parent, Reason} ->
            gen_tcp:close(Listen),
            exit(Reason);
        {'EXIT', _Acceptor, normal} ->
            listener_loop(Parent, Listen, Handler, Opts, Limit, Conns);
        {'EXIT', _Acceptor, Reason} ->
            limited(?LISTENER_LOG, fun() ->
                logger:error(iolist_to_binary(io_lib:format(
                    "redirect listener acceptor stopped: ~0p"
                    " (at most one such error a second is logged)", [Reason])))
            end),
            spawn_acceptor(Listen, Handler, Opts, Limit),
            listener_loop(Parent, Listen, Handler, Opts, Limit, Conns);
        _ ->
            listener_loop(Parent, Listen, Handler, Opts, Limit, Conns)
    end.

%% Tells the connections of every redirect listener of the node that it
%% drains (SIGTERM): the idle ones close at once, rather than at the end of
%% their idle timeout, so that their clients reconnect to another instance;
%% the others close after their response, as the handler says.
drain() ->
    Listeners = try pg:get_members(?SCOPE, ?SCOPE)
                catch error:badarg -> [] % no listener started yet
                end,
    lists:foreach(fun(Pid) -> Pid ! drain end, Listeners),
    nil.

%% Joins the pg group of the listeners, starting its scope with the first
%% one (pg scopes are not started by default). pg forgets a listener that
%% stops.
join_listeners() ->
    case whereis(?SCOPE) of
        undefined ->
            case pg:start(?SCOPE) of
                {ok, _} -> ok;
                {error, {already_started, _}} -> ok
            end;
        _ ->
            ok
    end,
    ok = pg:join(?SCOPE, ?SCOPE, self()).

spawn_acceptor(Listen, Handler, Opts, Limit) ->
    spawn_link(fun() -> accept(Listen, Handler, Opts, Limit) end).

accept(Listen, Handler, Opts, {_, Count, Cap} = Limit) ->
    case gen_tcp:accept(Listen) of
        {ok, Socket} ->
            %% the connections of this listener, and the ports of the whole
            %% VM: upstream connections, tunnels and files use ports too
            case atomics:add_get(Count, 1, 1) > Cap
                 orelse erlang:system_info(port_count) > port_cap() of
                true ->
                    %% closed before it costs a process
                    atomics:sub(Count, 1, 1),
                    gen_tcp:close(Socket),
                    limited(?LISTENER_LOG, fun() ->
                        logger:warning(iolist_to_binary(io_lib:format(
                            "redirect listener has ~B open connections, the VM ~B ports"
                            " of ~B: closing new connections"
                            " (at most one such warning a second is logged)",
                            [atomics:get(Count, 1), erlang:system_info(port_count),
                             erlang:system_info(port_limit)])))
                    end),
                    accept(Listen, Handler, Opts, Limit);
                false ->
                    try
                        serve(Socket, Handler, Opts, Limit)
                    catch
                        error:Reason ->
                            %% no process for it (system_limit): not counted
                            atomics:sub(Count, 1, 1),
                            gen_tcp:close(Socket),
                            backoff(Reason)
                    end,
                    accept(Listen, Handler, Opts, Limit)
            end;
        {error, closed} ->
            ok;
        {error, econnaborted} ->
            %% the client gave up before the connection was accepted
            accept(Listen, Handler, Opts, Limit);
        {error, Reason} ->
            %% out of file descriptors (emfile, enfile), or of memory
            backoff(Reason),
            accept(Listen, Handler, Opts, Limit)
    end.

%% A process for the accepted Socket, which the listener monitors.
serve(Socket, Handler, Opts, {Listener, _, _}) ->
    Pid = spawn_opt(fun() ->
        receive
            {go, S} -> connection(S, Handler, Opts)
        after 5000 ->
            exit(normal)
        end
    end, [{min_heap_size, ?CONN_HEAP}]),
    Listener ! {connection, Pid},
    case gen_tcp:controlling_process(Socket, Pid) of
        ok -> Pid ! {go, Socket};
        {error, _} -> gen_tcp:close(Socket), exit(Pid, kill)
    end.

%% 90% of the VM's port limit: room left for the other listeners, the
%% upstream connections and files.
port_cap() ->
    erlang:system_info(port_limit) * 9 div 10.

%% A pause rather than a loop that fails at once.
backoff(Reason) ->
    limited(?LISTENER_LOG, fun() ->
        logger:warning(iolist_to_binary(io_lib:format(
            "redirect listener cannot accept connections: ~0p"
            " (at most one such warning a second is logged)", [Reason])))
    end),
    timer:sleep(100).

%% ---------------------------------------------------------------------------
%% Connection
%% ---------------------------------------------------------------------------

connection(Socket, Handler, {options, IdleTimeout, MaxHead, WithPeer, Upstream}) ->
    Peer = case WithPeer of
        true -> peer(Socket);
        false -> {error, nil}
    end,
    %% exit_on_close: a client that shuts down its side after its request
    %% (half-close) still gets the response
    ok = inet:setopts(Socket, [{active, ?ACTIVE}, {exit_on_close, false}]),
    request(<<>>, #conn{
        socket = Socket,
        handler = Handler,
        peer = Peer,
        idle_timeout = IdleTimeout,
        max_head = MaxHead,
        upstream = Upstream
    }).

peer(Socket) ->
    case inet:peername(Socket) of
        {ok, {{A, B, C, D}, _}} -> {ok, {ip_v4, A, B, C, D}};
        {ok, {{A, B, C, D, E, F, G, H}, _}} -> {ok, {ip_v6, A, B, C, D, E, F, G, H}};
        _ -> {error, nil}
    end.

%% Waits for the next request, or for more bytes of a request head, then
%% parses it again. The socket delivers up to ?ACTIVE packets as messages
%% before it must be re-armed: no call to the port per request, and a
%% bounded mailbox. A head must be complete within the idle timeout of its
%% first bytes (the deadline): a 408 after that.
more(<<>>, #conn{idle_timeout = Timeout} = C) ->
    case hibernate_after(Timeout) of
        After when After < Timeout -> wait(<<>>, C, After, hibernate);
        _ -> wait(<<>>, C, Timeout, close)
    end;
more(Buffer, #conn{idle_timeout = Timeout, deadline = Deadline} = C) ->
    case Deadline - erlang:monotonic_time(millisecond) of
        Left when Left =< 0 ->
            expired(Buffer, C);
        Left ->
            case hibernate_after(Timeout) of
                After when After < Left -> wait(Buffer, C, After, hibernate);
                _ -> wait(Buffer, C, Left, close)
            end
    end.

%% Woken from hibernation: at the end of the idle timeout (or the deadline
%% of the head) by its timer, or by another message, then waited for until
%% End, that same end: a message that is not a request does not restart it.
%% (A `drain` from the listener is such a message: see `drained/3`.) A
%% message of the kept upstream connection (closed by the upstream, or bytes
%% nothing asked for) is not: the connection is dropped, and the process
%% hibernates again.
idle(Buffer, C, Timer, End) ->
    receive
        {timeout, Timer, idle} -> pending(Buffer, C, fun() -> expired(Buffer, C) end)
    after 0 ->
        case upstream_event(C) of
            true ->
                erlang:hibernate(?MODULE, idle, [Buffer, close_upstream(C), Timer, End]);
            false ->
                case erlang:cancel_timer(Timer) of
                    false -> receive {timeout, Timer, idle} -> ok after 0 -> ok end;
                    _ -> ok
                end,
                wait(Buffer, C, max(0, End - erlang:monotonic_time(millisecond)), close)
        end
    end.

%% Whether the kept upstream connection sent a message (it is then of no use).
upstream_event(#conn{up = none}) ->
    false;
upstream_event(#conn{up = Up}) ->
    up_await(Up, 0) =/= {error, timeout}.

%% Bytes that came with the message that woke the connection up are read
%% before it gives up on them: else Then().
pending(Buffer, #conn{socket = Socket} = C, Then) ->
    receive
        {tcp, Socket, Data} when Buffer =:= <<>> -> request(Data, C);
        {tcp, Socket, Data} -> more_head(<<Buffer/binary, Data/binary>>, Data, C)
    after 0 ->
        Then()
    end.

%% The listener says the node drains (SIGTERM, `drain/0`): a connection
%% between requests closes, so that its client reconnects to another
%% instance before this one stops. One reading a request head ignores it
%% (`wait/4` only takes it between requests), and closes after the
%% response; so does one whose `drain` is stale (tests clear the flag).
drained(C, Timeout, Then) ->
    case redirect_proxy_sigterm:draining() of
        true -> pending(<<>>, C, fun() -> close(C) end);
        false -> wait(<<>>, C, Timeout, Then)
    end.

%% 1 s, or half the idle timeout when it is shorter (tests)
hibernate_after(Timeout) -> min(1000, Timeout div 2).

wait(Buffer, #conn{socket = Socket} = C, Timeout, Then) ->
    Up = up_socket(C),
    receive
        %% usually a whole request: parsed as it came, not copied first
        {tcp, Socket, Data} when Buffer =:= <<>> ->
            request(Data, C);
        {tcp, Socket, Data} ->
            more_head(<<Buffer/binary, Data/binary>>, Data, C);
        {tcp_passive, Socket} ->
            case inet:setopts(Socket, [{active, ?ACTIVE}]) of
                ok -> more(Buffer, C);
                {error, _} -> close(C)
            end;
        %% the replies to `send/2`: queued (it waits for the socket) or sent
        {inet_reply, Socket, sent} ->
            more(Buffer, C);
        {inet_reply, Socket, ok, sent} ->
            more(Buffer, C);
        {inet_reply, Socket, _, sent} ->
            close(C);
        {tcp_closed, Socket} ->
            close(C);
        {tcp_error, Socket, _} ->
            close(C);
        drain when Buffer =:= <<>> ->
            drained(C, Timeout, Then);
        %% the kept upstream connection, closed by the upstream or sending
        %% bytes nothing asked for: dropped (more/2 then waits as before:
        %% the head keeps its deadline, and the process hibernates)
        {Tag, Up, _} when Tag =:= tcp; Tag =:= ssl; Tag =:= tcp_error; Tag =:= ssl_error ->
            more(Buffer, close_upstream(C));
        {Tag, Up} when Tag =:= tcp_closed; Tag =:= ssl_closed ->
            more(Buffer, close_upstream(C))
    after Timeout ->
        case Then of
            close -> expired(Buffer, C);
            hibernate ->
                %% for the rest of the idle timeout, or of the time left to
                %% complete the head
                End = case Buffer of
                    <<>> -> erlang:monotonic_time(millisecond) + C#conn.idle_timeout - Timeout;
                    _ -> C#conn.deadline
                end,
                %% a message: a hibernated process only wakes up for one
                Timer = erlang:start_timer(
                    max(0, End - erlang:monotonic_time(millisecond)), self(), idle),
                erlang:hibernate(?MODULE, idle, [Buffer, C, Timer, End])
        end
    end.

%% The end of the idle timeout: an incomplete request head gets a 408.
expired(<<>>, C) -> close(C);
expired(_, C) -> reject(408, C).

%% More bytes of an incomplete head. Each parse starts over from the first
%% byte, so the head is parsed again only when it may have changed the
%% outcome: once its request line is complete (an invalid one is refused
%% early), once the new bytes may end the head (an empty line), or once it
%% reaches max_head. Parsing it at every new line would let a client
%% sending one header line per packet make the server parse a head of up to
%% max_head bytes thousands of times.
more_head(Buffer, Data, #conn{max_head = Max} = C) ->
    Size = byte_size(Buffer),
    Previous = Size - byte_size(Data),
    case Size >= Max orelse head_may_end(Buffer, Previous) of
        true -> request(Buffer, C);
        false -> more(Buffer, C)
    end.

%% Whether a parse of Buffer, whose first Previous bytes were already
%% parsed, may not say `more`.
head_may_end(Buffer, Previous) ->
    case binary:match(Buffer, <<"\n">>) of
        nomatch ->
            false;
        {First, _} when First >= Previous ->
            %% the request line just completed
            true;
        _ ->
            %% an empty line among the new bytes (or across the boundary)
            Start = max(0, Previous - 2),
            binary:match(Buffer, [<<"\n\n">>, <<"\n\r\n">>],
                         [{scope, {Start, byte_size(Buffer) - Start}}]) =/= nomatch
    end.

request(<<>>, C) ->
    more(<<>>, C);
request(Buffer, #conn{max_head = Max} = C) ->
    case parse(Buffer) of
        {ok, Request, Version, Close, Rest} when C#conn.deadline =:= none ->
            respond(Request, Version, Close, Rest, C);
        {ok, Request, Version, Close, Rest} ->
            respond(Request, Version, Close, Rest, C#conn{deadline = none});
        more when byte_size(Buffer) >= Max ->
            %% 414 while the request line itself is incomplete
            Status = case binary:match(Buffer, <<"\n">>) of
                nomatch -> 414;
                _ -> 431
            end,
            reject(Status, C);
        more when C#conn.deadline =:= none ->
            Deadline = erlang:monotonic_time(millisecond) + C#conn.idle_timeout,
            more(Buffer, C#conn{deadline = Deadline});
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

%% An absolute path, with only the characters of a URI (RFC 3986), plus the
%% ones browsers leave unescaped (`?URI_CHAR`): a raw backslash, space, `"`,
%% `<`, `>`, DEL, control character or non-ASCII byte gets a 400, so that no
%% CR or LF can reach a `location` header. The positions of the first `?`
%% and `#` are noted on the way.
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
                %% repeated: one list, as when forwarding (framing/8)
                <<"connection">> when Connection =:= <<>> ->
                    headers(Rest, [Header | Acc], Host, Body, Value);
                <<"connection">> ->
                    headers(Rest, [Header | Acc], Host, Body,
                            <<Connection/binary, ", ", Value/binary>>);
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
%% and in responses
lowercase_name(<<"Date">>) -> <<"date">>;
lowercase_name(<<"Server">>) -> <<"server">>;
lowercase_name(<<"Content-Encoding">>) -> <<"content-encoding">>;
lowercase_name(<<"Last-Modified">>) -> <<"last-modified">>;
lowercase_name(<<"ETag">>) -> <<"etag">>;
lowercase_name(<<"Vary">>) -> <<"vary">>;
lowercase_name(<<"Location">>) -> <<"location">>;
lowercase_name(<<"Set-Cookie">>) -> <<"set-cookie">>;
lowercase_name(<<"Keep-Alive">>) -> <<"keep-alive">>;
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
%% Forwarding to the upstream
%% ---------------------------------------------------------------------------
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

-define(CONNECT_TIMEOUT, 5000).
%% the process dictionary key of the bytes a relayed response has yet to
%% send to the client (relay_body/6)
-define(RELAYED, '$redirect_proxy_relayed').
-define(MAX_RESPONSE_HEAD, 65536).

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
    retry
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
        {ok, Body, Tokens, Upgrade, Expect, HasHost} ->
            Up = C#conn.upstream,
            %% the client's values of the headers the handler sets, and of
            %% the ones it drops (forwarding headers from untrusted peers)
            Drop = [T || T <- Tokens, not essential(T)]
                ++ [N || {N, _} <- XForwarded] ++ Dropped,
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
%% is dropped with `x-real-ip`.
request_headers([{Name, Value} | Rest], Drop) ->
    case Name of
        _ when ?HOP_BY_HOP(Name) -> request_headers(Rest, Drop);
        <<"expect">> -> request_headers(Rest, Drop);
        <<"content-length">> -> request_headers(Rest, Drop);
        _ ->
            Dropped = lists:member(Name, Drop) orelse case binary:match(Name, <<"_">>) of
                nomatch -> false;
                _ -> lists:member(binary:replace(Name, <<"_">>, <<"-">>, [global]), Drop)
            end,
            case Dropped of
                true -> request_headers(Rest, Drop);
                false -> [Name, <<": ">>, Value, <<"\r\n">> | request_headers(Rest, Drop)]
            end
    end;
request_headers([], _) ->
    [].

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
    case copy_chunked(Rest, client_recv(C), chunk_emit(Emit), 0) of
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
            response(Socket, false, Buffer1, Rest, BodyDone, F, C);
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
            {Date, C1} = case HasDate of
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
                    case ClientKeep of
                        true -> request(Rest, C2);
                        false -> close(C2)
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

%% Calls Log at most once a second for the whole node, per Kind of message.
limited(Kind, Log) ->
    Now = erlang:system_time(second),
    case atomics:exchange(persistent_term:get(?WARNED), Kind, Now) of
        Now -> ok;
        _ -> Log()
    end.

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
emit(Emit, Data) -> Emit(Data).

chunk_emit(Emit) ->
    fun(Data) ->
        Emit([integer_to_binary(byte_size(Data), 16), <<"\r\n">>, Data, <<"\r\n">>])
    end.

%% The client's bytes, from the socket's messages.
client_recv(#conn{socket = Socket, upstream = #up{timeout = Timeout}}) ->
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

%% The socket of the kept upstream connection, that its messages carry.
up_socket(#conn{up = none}) -> none;
up_socket(#conn{up = {_, S}}) -> S.

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
upstream_settings({some, {upstream, Tls, Host, Port, Timeout, Verify}}) ->
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
        authority = Authority, url = <<Scheme/binary, Authority/binary>>,
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

%% ---------------------------------------------------------------------------
%% Responses
%% ---------------------------------------------------------------------------

respond(Request0, Version, Close0, Rest,
        #conn{handler = Handler, peer = Peer} = C) ->
    Request = setelement(4, Request0, Peer),
    Head = element(2, Request) =:= head,
    case call(Handler, Request) of
        {ok, {answer, {response, Status, Headers, Body}}} ->
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
            case Close of
                true ->
                    _ = gen_tcp:send(C1#conn.socket, Response),
                    %% the body of the request is not read: closing at once
                    %% could reset the connection before the client reads
                    %% the response
                    case has_body(element(3, Request0)) of
                        true -> linger_close(C1);
                        false -> close(C1)
                    end;
                false ->
                    case send(C1#conn.socket, Response) of
                        ok -> request(Rest, C1);
                        error -> close(C1)
                    end
            end;
        {ok, {forward, CloseAfter, XForwarded, Drop, Done}} ->
            forward(Request, Version, Rest, CloseAfter, {XForwarded, Drop}, Done, C);
        error ->
            reject(500, C)
    end.

%% A response on a kept-alive connection. `gen_tcp:send/2` monitors the
%% port, encodes the monitor as the caller tag, then waits for the driver's
%% reply: the process is scheduled out and in again for every response.
%% This gives the driver a constant tag and does not wait: `more/2` takes
%% the reply with the next request, and closes the connection if it is an
%% error. A busy port (`send_timeout`, high watermark) still suspends the
%% process, as `gen_tcp:send/2` does.
send(Socket, Data) ->
    try erlang:port_command(Socket, [?SEND_TAG | Data]) of
        true -> ok
    catch
        error:_ -> error
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

%% An empty response, then the connection is closed (lingering: the rest
%% of the request is not read).
reject(Status, C) ->
    {Date, C1} = date(C),
    _ = gen_tcp:send(C1#conn.socket, [
        status_line(Status),
        <<"content-length: 0\r\ndate: ">>, Date,
        <<"\r\ncache-control: no-store\r\nconnection: close\r\n\r\n">>
    ]),
    linger_close(C1).

close(#conn{socket = Socket} = C) ->
    _ = close_upstream(C),
    gen_tcp:close(Socket),
    exit(normal).

%% Whether a request announces a body (one the answered path does not read).
has_body([{<<"transfer-encoding">>, _} | _]) -> true;
has_body([{<<"content-length">>, V} | _]) when V =/= <<"0">> -> true;
has_body([_ | Rest]) -> has_body(Rest);
has_body([]) -> false.

%% Closes a connection whose client may still be sending: a socket closed
%% with unread bytes, or bytes arriving after it is closed, is reset, and a
%% reset can discard the response before the client reads it. The response
%% goes out first (`shutdown` waits for it), then what the client sends is
%% read and discarded until it closes, for at most ?LINGER_MS (?LINGER_IDLE_MS
%% without a byte) or ?LINGER_BYTES, as nginx's `lingering_close`.
linger_close(#conn{socket = Socket} = C) ->
    _ = close_upstream(C),
    case gen_tcp:shutdown(Socket, write) of
        ok ->
            _ = inet:setopts(Socket, [{active, false}]),
            linger(Socket, erlang:monotonic_time(millisecond) + ?LINGER_MS,
                   ?LINGER_BYTES);
        {error, _} ->
            ok
    end,
    gen_tcp:close(Socket),
    exit(normal).

linger(Socket, End, Left) when Left > 0 ->
    case min(?LINGER_IDLE_MS, End - erlang:monotonic_time(millisecond)) of
        Wait when Wait > 0 ->
            case gen_tcp:recv(Socket, 0, Wait) of
                {ok, Data} -> linger(Socket, End, Left - byte_size(Data));
                {error, _} -> ok
            end;
        _ ->
            ok
    end;
linger(_, _, _) ->
    ok.

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

status_line(100) -> <<"HTTP/1.1 100 Continue\r\n">>;
status_line(101) -> <<"HTTP/1.1 101 Switching Protocols\r\n">>;
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
status_line(408) -> <<"HTTP/1.1 408 Request Timeout\r\n">>;
status_line(410) -> <<"HTTP/1.1 410 Gone\r\n">>;
status_line(414) -> <<"HTTP/1.1 414 URI Too Long\r\n">>;
status_line(431) -> <<"HTTP/1.1 431 Request Header Fields Too Large\r\n">>;
status_line(451) -> <<"HTTP/1.1 451 Unavailable For Legal Reasons\r\n">>;
status_line(500) -> <<"HTTP/1.1 500 Internal Server Error\r\n">>;
status_line(502) -> <<"HTTP/1.1 502 Bad Gateway\r\n">>;
status_line(503) -> <<"HTTP/1.1 503 Service Unavailable\r\n">>;
status_line(504) -> <<"HTTP/1.1 504 Gateway Timeout\r\n">>;
status_line(505) -> <<"HTTP/1.1 505 HTTP Version Not Supported\r\n">>;
status_line(Status) ->
    [<<"HTTP/1.1 ">>, integer_to_binary(Status), <<" ">>,
     reason(Status div 100), <<"\r\n">>].

reason(1) -> <<"Informational">>;
reason(2) -> <<"Success">>;
reason(3) -> <<"Redirection">>;
reason(4) -> <<"Client Error">>;
reason(_) -> <<"Server Error">>.
