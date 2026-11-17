%% The HTTP/1.1 server of the redirect listener.
%%
%% The redirect listener answers small requests with small responses: no
%% TLS, no request bodies (they are never read: the connection is closed
%% after the response), no upgrades. This server does just that, with as
%% little work per request as possible:
%%
%% - a pool of acceptors, up to a number of open connections, and of ports
%%   in the VM (90 % of its port limit: a connection over it is closed at
%%   once, rather than the VM running out of ports), and of open
%%   connections per client address (`max_connections_per_ip`, an IPv6 /64
%%   counting as one address; loopback and trusted proxies are not
%%   limited): one client
%%   cannot take them all; one process per connection, its socket in
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
%% it instead of answering (`Forward`): see `redirect_proxy_upstream`.
%% The body of a forwarded request is read and forwarded, and the connection
%% kept alive after it when its framing was unambiguous.
-module(redirect_proxy_http).

-include("redirect_proxy_http.hrl").

-export([start/4, drain/0]).
%% internal
-export([init/5, parse/1, idle/4]).
%% for redirect_proxy_upstream: the connection loop, responses, logging and
%% the parser's helpers
-export([request/2, close/1, reject/2, linger_close/1, date/1, limited/2,
         close_requested/2, has_token/2, lowercase/1, lowercase_name/1, name/3,
         token/2, skip_ows/1]).

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

%% characters of a host name in a Host header: a URI's reg-name (RFC 3986
%% 3.2.2: unreserved, sub-delims and `%`)
-define(REG_NAME(C),
    ((C >= $a andalso C =< $z) orelse (C >= $A andalso C =< $Z)
     orelse (C >= $0 andalso C =< $9)
     orelse C =:= $- orelse C =:= $. orelse C =:= $_ orelse C =:= $~
     orelse C =:= $% orelse C =:= $! orelse C =:= $$ orelse C =:= $&
     orelse C =:= $' orelse C =:= $( orelse C =:= $) orelse C =:= $*
     orelse C =:= $+ orelse C =:= $, orelse C =:= $; orelse C =:= $=)).

%% header lines in a request head (nginx and Apache allow about as many)
-define(MAX_HEADERS, 100).

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

%% atomics: the second of the last warning of each kind (?UPSTREAM_LOG...,
%% in redirect_proxy_http.hrl)
-define(WARNED, {?MODULE, warned}).

%% The pg scope, and group, of the redirect listeners (`drain/0`).
-define(SCOPE, redirect_proxy_listeners).

%% Opts: the Gleam `Options(idle_timeout_ms, max_head_bytes, peer, upstream,
%% max_connections_per_ip, unlimited_peers)`; tests can add the connection
%% cap (`{options, ..., MaxConnections}`).
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

init(Parent, Address, Port, Handler,
     {options, Idle, MaxHead, Peer, Upstream, PerIp, Unlimited}) ->
    Cap = max(1, port_cap()),
    init(Parent, Address, Port, Handler,
         {options, Idle, MaxHead, Peer, Upstream, PerIp, Unlimited, Cap});
init(Parent, Address, Port, Handler,
     {options, Idle, MaxHead, Peer, Upstream, PerIp, Unlimited, Cap}) ->
    process_flag(trap_exit, true),
    warned_init(),
    Opts = {options, Idle, MaxHead, Peer,
            redirect_proxy_upstream:upstream_settings(Upstream)},
    %% the open connections, and their cap; per client address: the
    %% counts (#{Address => N} in an ETS table), the cap and the peers it
    %% does not apply to
    PerAddress = case PerIp of
        0 -> none;
        _ -> {ets:new(?MODULE, [set, public, {write_concurrency, true}]),
              PerIp, Unlimited}
    end,
    Limit = {self(), atomics:new(1, []), Cap, PerAddress},
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
listener_loop(Parent, Listen, Handler, Opts, {_, Count, _, PerAddress} = Limit, Conns) ->
    receive
        {connection, Pid, Key} ->
            _ = erlang:monitor(process, Pid),
            listener_loop(Parent, Listen, Handler, Opts, Limit, Conns#{Pid => Key});
        {'DOWN', _, process, Pid, _} ->
            atomics:sub(Count, 1, 1),
            release(PerAddress, maps:get(Pid, Conns, none)),
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

accept(Listen, Handler, Opts, {_, Count, Cap, PerAddress} = Limit) ->
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
                    case claim(PerAddress, Socket) of
                        {ok, Key, Ip} ->
                            try
                                serve(Socket, Handler, Opts, Limit, Key, Ip)
                            catch
                                error:Reason ->
                                    %% no process for it (system_limit): not counted
                                    atomics:sub(Count, 1, 1),
                                    release(PerAddress, Key),
                                    gen_tcp:close(Socket),
                                    backoff(Reason)
                            end;
                        {over, Address, N} ->
                            atomics:sub(Count, 1, 1),
                            gen_tcp:close(Socket),
                            limited(?ADDRESS_LOG, fun() ->
                                logger:warning(iolist_to_binary(io_lib:format(
                                    "redirect listener: ~ts has ~B open connections"
                                    " (server.max_connections_per_ip): closing new ones"
                                    " (at most one such warning a second is logged)",
                                    [Address, N])))
                            end)
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

%% Counts a connection against its client address: {ok, Key, Ip} (Key
%% none when not counted: no limit, a trusted proxy, an unknown address;
%% Ip unknown when not looked up), or {over, Address, Open} past the cap.
claim(none, _) ->
    {ok, none, unknown};
claim({Tab, Max, Unlimited}, Socket) ->
    case inet:peername(Socket) of
        {ok, {Ip, _}} ->
            case redirect_proxy_net_ffi:cidrs_contain_ip(Ip, Unlimited) of
                true ->
                    {ok, none, Ip};
                false ->
                    Key = redirect_proxy_net_ffi:client_group(Ip),
                    case ets:update_counter(Tab, Key, {2, 1}, {Key, 0}) of
                        N when N > Max ->
                            release({Tab, Max, Unlimited}, Key),
                            {over, redirect_proxy_net_ffi:client_group_text(Key), N - 1};
                        _ ->
                            {ok, Key, Ip}
                    end
            end;
        _ ->
            {ok, none, unknown}
    end.

%% Runs in the listener: a counting mistake (a key released twice) must
%% not take it down with every connection slot.
release(_, none) ->
    ok;
release({Tab, _, _}, Key) ->
    %% the last one: the entry goes (delete_object: unless another
    %% connection of the address counted itself in the meantime)
    try ets:update_counter(Tab, Key, {2, -1}) of
        N when N =< 0 -> ets:delete_object(Tab, {Key, N});
        _ -> true
    catch
        error:badarg -> true
    end,
    ok.

%% A process for the accepted Socket, which the listener monitors, and the
%% Key it counts under (release/2 when it ends).
serve(Socket, Handler, Opts, {Listener, _, _, _}, Key, Ip) ->
    Pid = spawn_opt(fun() ->
        receive
            {go, S} -> connection(S, Handler, Opts, Ip)
        after 5000 ->
            exit(normal)
        end
    end, [{min_heap_size, ?CONN_HEAP}]),
    Listener ! {connection, Pid, Key},
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

%% Creates the ?WARNED atomics, or replaces them when they have fewer slots
%% than this version uses (left by an older version of the module: a hot
%% upgrade must not make limited/2 fail with badarg).
warned_init() ->
    case persistent_term:get(?WARNED, undefined) of
        undefined -> persistent_term:put(?WARNED, atomics:new(?WARNED_KINDS, []));
        Ref ->
            case maps:get(size, atomics:info(Ref)) < ?WARNED_KINDS of
                true -> persistent_term:put(?WARNED, atomics:new(?WARNED_KINDS, []));
                false -> ok
            end
    end.

%% Calls Log at most once a second for the whole node, per Kind of message.
limited(Kind, Log) ->
    Now = erlang:system_time(second),
    case atomics:exchange(persistent_term:get(?WARNED), Kind, Now) of
        Now -> ok;
        _ -> Log()
    end.

%% ---------------------------------------------------------------------------
%% Connection
%% ---------------------------------------------------------------------------

%% Ip: the peer address when the acceptor looked it up (unknown otherwise).
connection(Socket, Handler, {options, IdleTimeout, MaxHead, WithPeer, Upstream}, Ip) ->
    Peer = case {WithPeer, Ip} of
        {false, _} -> {error, nil};
        {true, unknown} -> peer(Socket);
        {true, _} -> peer_address(Ip)
    end,
    %% exit_on_close: a client that shuts down its side after its request
    %% (half-close) still gets the response
    %% a client gone before this process got the socket: nothing to answer
    case inet:setopts(Socket, [{active, ?ACTIVE}, {exit_on_close, false}]) of
        ok -> ok;
        {error, _} -> gen_tcp:close(Socket), exit(normal)
    end,
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
        {ok, {Ip, _}} -> peer_address(Ip);
        _ -> {error, nil}
    end.

peer_address({A, B, C, D}) -> {ok, {ip_v4, A, B, C, D}};
peer_address({A, B, C, D, E, F, G, H}) -> {ok, {ip_v6, A, B, C, D, E, F, G, H}};
peer_address(_) -> {error, nil}.

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
    redirect_proxy_upstream:up_await(Up, 0) =/= {error, timeout}.

%% The socket of the kept upstream connection, that its messages carry.
up_socket(#conn{up = none}) -> none;
up_socket(#conn{up = {_, S}}) -> S.

%% Closes the kept upstream connection: nothing to do without one, as on
%% the redirect path.
close_upstream(#conn{up = none} = C) -> C;
close_upstream(C) -> redirect_proxy_upstream:close_upstream(C).

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
%% Closed at once: lingering would keep a client too slow to send its head
%% (a slow-head attack) for longer.
expired(_, C) -> close(send_reject(408, C)).

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
    case Size >= Max orelse head_may_end(Buffer, Data, Previous) of
        true -> request(Buffer, C);
        false -> more(Buffer, C)
    end.

%% Whether a parse of Buffer, whose first Previous bytes were already
%% parsed, may not say `more`. Both a request line and an empty line end
%% with a LF among the new bytes (Data): without one, the head is not
%% scanned again (a request line trickled byte by byte would be scanned
%% once per byte).
head_may_end(Buffer, Data, Previous) ->
    case binary:match(Data, <<"\n">>) of
        nomatch ->
            false;
        _ ->
            case binary:match(Buffer, <<"\n">>) of
                {First, _} when First >= Previous ->
                    %% the request line just completed
                    true;
                _ ->
                    %% an empty line among the new bytes (or across the
                    %% boundary)
                    Start = max(0, Previous - 2),
                    binary:match(Buffer, [<<"\n\n">>, <<"\n\r\n">>],
                                 [{scope, {Start, byte_size(Buffer) - Start}}]) =/= nomatch
            end
    end.

request(<<>>, C) ->
    more(<<>>, C);
request(Buffer, #conn{max_head = Max} = C) ->
    case parse(Buffer) of
        {ok, _, _, _, Rest} when byte_size(Buffer) - byte_size(Rest) > Max ->
            %% a head that came whole, in one packet, is no longer allowed
            %% than one that came in several
            reject(431, C);
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
%% Blank lines before a request line are ignored (RFC 9112 2.2), up to
%% ?MAX_BLANK_LINES: a head made only of blank lines is not complete, so
%% each new packet of it would be parsed again from its first byte, up to
%% max_head bytes.
-define(MAX_BLANK_LINES, 8).
parse(Buffer) -> parse(Buffer, 0).

parse(<<"\r\n", _/binary>>, ?MAX_BLANK_LINES) -> {error, 400};
parse(<<"\n", _/binary>>, ?MAX_BLANK_LINES) -> {error, 400};
parse(<<"\r\n", Rest/binary>>, N) -> parse(Rest, N + 1);
parse(<<"\n", Rest/binary>>, N) -> parse(Rest, N + 1);
parse(<<"\r">>, _) -> more;
parse(Buffer, _) -> method(Buffer).

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
        {ok, Headers, _, _, _, _} when length(Headers) > ?MAX_HEADERS ->
            {error, 431};
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
    case authority(Host) of
        {ok, HostName, Port} ->
            request(Method, Target0, Query0, Fragment, Version, Headers,
                    HostName, Port, Body, Connection, Rest);
        error ->
            {error, 400}
    end.

request(Method, Target0, Query0, Fragment, Version, Headers, HostName, Port,
        Body, Connection, Rest) ->
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

%% The Host header (RFC 9110 7.2): `host [":" port]`, the host a name of at
%% most 255 bytes (letters, digits and the other characters of a URI's
%% reg-name: no space, `/`, `@`, `?`, `#` or non-ASCII byte), an IPv4
%% address or a bracketed IPv6 one. {ok, Host, Port} (80 when there is no
%% port) or error. The length bound keeps every later host walk (wildcard
%% rules look up each parent domain) short.
-define(MAX_HOST, 255).

authority(<<"[", _/binary>> = Host) ->
    case binary:match(Host, <<"]">>) of
        {Close, 1} when Close =< ?MAX_HOST ->
            <<Literal:(Close + 1)/binary, Port/binary>> = Host,
            case ip_literal(binary:part(Literal, 1, Close - 1)) of
                true -> port(Literal, Port);
                false -> error
            end;
        _ ->
            error
    end;
authority(Host) ->
    authority(Host, 0).

authority(Host, N) ->
    case Host of
        <<_:N/binary, C, _/binary>> when ?REG_NAME(C), N < ?MAX_HOST ->
            authority(Host, N + 1);
        <<Name:N/binary, $:, Port/binary>> ->
            port(Name, <<$:, Port/binary>>);
        <<_:N/binary>> ->
            {ok, Host, 80};
        _ ->
            error
    end.

%% `:digits`, at most 65535; an empty port (`host:`) is the default one.
port(Name, <<>>) -> {ok, Name, 80};
port(Name, <<":">>) -> {ok, Name, 80};
port(Name, <<":", Digits/binary>>) when byte_size(Digits) =< 5 ->
    case all_digits(Digits) andalso binary_to_integer(Digits) of
        P when is_integer(P), P =< 65535 -> {ok, Name, P};
        _ -> error
    end;
port(_, _) -> error.

all_digits(<<C, Rest/binary>>) when C >= $0, C =< $9 -> all_digits(Rest);
all_digits(<<>>) -> true;
all_digits(_) -> false.

%% Inside the brackets: an IPv6 address (possibly ending with an IPv4 one).
ip_literal(Address) ->
    case inet:parse_ipv6strict_address(binary_to_list(Address)) of
        {ok, _} -> true;
        {error, _} -> false
    end.

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
                %% a redirect's empty body: no size to compute or format
                _ when Body =:= [] -> <<"content-length: 0\r\n">>;
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
            redirect_proxy_upstream:forward(Request, Version, Rest, CloseAfter,
                                           {XForwarded, Drop}, Done, C);
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
    linger_close(send_reject(Status, C)).

send_reject(Status, C) ->
    {Date, C1} = date(C),
    _ = gen_tcp:send(C1#conn.socket, [
        status_line(Status),
        <<"content-length: 0\r\ndate: ">>, Date,
        <<"\r\ncache-control: no-store\r\nconnection: close\r\n\r\n">>
    ]),
    C1.

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
status_line(413) -> <<"HTTP/1.1 413 Content Too Large\r\n">>;
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
