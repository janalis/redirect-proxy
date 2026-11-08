%% Test helper: an unused TCP port on the loopback interface.
-module(test_net_ffi).
-export([free_port/0, set_mtime_ago/2, counting_server/0, accepted/1, format_json_log/2,
         raw_exchange/2, session/3, paced_session/4, half_closed/3, reset_after/3, parse_outcome/1,
         trickle/3]).

free_port() ->
    {ok, Socket} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Socket),
    ok = gen_tcp:close(Socket),
    Port.

set_mtime_ago(Path, SecondsAgo) ->
    Time = erlang:system_time(second) - SecondsAgo,
    ok = file:change_time(Path, calendar:system_time_to_local_time(Time, second)),
    nil.

%% A TCP server that counts connections and closes each one at once (a broken
%% upstream). Returns {Port, Counter}.
counting_server() ->
    Counter = counters:new(1, []),
    Self = self(),
    spawn(fun() ->
        {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
        {ok, Port} = inet:port(L),
        Self ! {port, Port},
        accept_loop(L, Counter)
    end),
    receive {port, Port} -> {Port, Counter} end.

accept_loop(L, Counter) ->
    case gen_tcp:accept(L) of
        {ok, S} ->
            counters:add(Counter, 1, 1),
            gen_tcp:close(S),
            accept_loop(L, Counter);
        _ -> ok
    end.

accepted(Counter) -> counters:get(Counter, 1).

%% One line of the JSON application log formatter (without the newline).
format_json_log(Level, Message) ->
    Event = #{level => binary_to_atom(Level), msg => {string, Message},
              meta => #{time => logger:timestamp(), domain => [redirect_proxy, test]}},
    Line = iolist_to_binary(redirect_proxy_log_json:format(Event, #{})),
    binary:part(Line, 0, byte_size(Line) - 1).

%% Sends each chunk on one TCP connection to 127.0.0.1:Port, 100 ms apart (so
%% that they arrive as separate packets), then returns every byte received
%% until the server closes the connection or 1 s of silence.
raw_exchange(Port, Chunks) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    lists:foreach(fun(C) -> gen_tcp:send(S, C), timer:sleep(100) end, Chunks),
    Received = read_all(S, <<>>),
    gen_tcp:close(S),
    Received.

read_all(S, Acc) ->
    case gen_tcp:recv(S, 0, 1000) of
        {ok, Data} -> read_all(S, <<Acc/binary, Data/binary>>);
        {error, _} -> Acc
    end.

%% Sends each chunk on one connection (50 ms apart), then reads until the
%% server closes it or WaitMs of silence. Returns {Received, Closed}.
session(Port, Chunks, WaitMs) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    lists:foreach(fun(C) -> gen_tcp:send(S, C), timer:sleep(50) end, Chunks),
    Result = read_until_closed(S, <<>>, WaitMs),
    gen_tcp:close(S),
    Result.

%% Like session/3, with GapMs between the chunks.
paced_session(Port, Chunks, GapMs, WaitMs) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    lists:foreach(fun(C) -> gen_tcp:send(S, C), timer:sleep(GapMs) end, Chunks),
    Result = read_until_closed(S, <<>>, WaitMs),
    gen_tcp:close(S),
    Result.

%% Sends Data, shuts down the sending side (half-close), then reads until
%% the server closes the connection or WaitMs of silence. Returns
%% {Received, Closed}.
half_closed(Port, Data, WaitMs) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port,
                              [binary, {active, false}, {exit_on_close, false}]),
    ok = gen_tcp:send(S, Data),
    ok = gen_tcp:shutdown(S, write),
    Result = read_until_closed(S, <<>>, WaitMs),
    gen_tcp:close(S),
    Result.

%% Sends Data, reads nothing for WaitMs, then resets the connection.
reset_after(Port, Data, WaitMs) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port,
                              [binary, {active, false}, {linger, {true, 0}},
                               {recbuf, 4096}]),
    ok = gen_tcp:send(S, Data),
    timer:sleep(WaitMs),
    gen_tcp:close(S),
    nil.

read_until_closed(S, Acc, WaitMs) ->
    case gen_tcp:recv(S, 0, WaitMs) of
        {ok, Data} -> read_until_closed(S, <<Acc/binary, Data/binary>>, WaitMs);
        {error, closed} -> {Acc, true};
        {error, _} -> {Acc, false}
    end.

%% The outcome of parsing a request head: "ok", "more" or "error:<status>".
parse_outcome(Head) ->
    case redirect_proxy_http:parse(Head) of
        {ok, _, _, _, _} -> <<"ok">>;
        more -> <<"more">>;
        {error, Status} -> <<"error:", (integer_to_binary(Status))/binary>>
    end.

%% Sends Data one byte at a time, GapMs apart, until the server answers or
%% closes the connection, then reads until it closes it or 1 s of silence.
%% Returns {Received, Closed}.
trickle(Port, Data, GapMs) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    Result = trickle_bytes(S, Data, GapMs),
    gen_tcp:close(S),
    Result.

trickle_bytes(S, <<Byte, Rest/binary>>, GapMs) ->
    _ = gen_tcp:send(S, <<Byte>>),
    case gen_tcp:recv(S, 0, GapMs) of
        {ok, Data} -> read_until_closed(S, Data, 1000);
        {error, timeout} -> trickle_bytes(S, Rest, GapMs);
        {error, _} -> {<<>>, true}
    end;
trickle_bytes(S, <<>>, _) ->
    read_until_closed(S, <<>>, 1000).
