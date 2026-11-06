%% Test helper: an unused TCP port on the loopback interface.
-module(test_net_ffi).
-export([free_port/0, set_mtime_ago/2, counting_server/0, accepted/1]).

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
