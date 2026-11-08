%% Microstate accounting for the Benchmark workflow (`bench-compare.py
%% --profile`): where the schedulers spend their time under load (emulator,
%% port, check_io, sleep...). Internal and undocumented.
%%
%% With RP_BENCH_MSACC=<seconds>, a process waits for the file
%% /tmp/rp-msacc-start, then measures for that many seconds and prints one
%% line per thread type to stdout:
%%
%%     msacc scheduler emulator=61.2% port=20.1% check_io=4.0% sleep=9.1% ...
%%
%% Uses the erts BIFs directly: the `msacc` module of runtime_tools is not
%% in the bundle.
-module(redirect_proxy_msacc).

-export([start/0]).

-define(TRIGGER, "/tmp/rp-msacc-start").

start() ->
    case os:getenv("RP_BENCH_MSACC") of
        false ->
            nil;
        Value ->
            case string:to_integer(Value) of
                {Seconds, ""} when Seconds > 0 ->
                    _ = spawn(fun() -> wait(Seconds) end),
                    nil;
                _ ->
                    nil
            end
    end.

wait(Seconds) ->
    case filelib:is_regular(?TRIGGER) of
        true ->
            measure(Seconds);
        false ->
            timer:sleep(100),
            wait(Seconds)
    end.

measure(Seconds) ->
    _ = erlang:system_flag(microstate_accounting, reset),
    _ = erlang:system_flag(microstate_accounting, true),
    timer:sleep(Seconds * 1000),
    Stats = erlang:statistics(microstate_accounting),
    _ = erlang:system_flag(microstate_accounting, false),
    _ = file:delete(?TRIGGER),
    ByType = lists:foldl(fun(#{type := Type, counters := Counters}, Acc) ->
        maps:update_with(Type, fun(Old) -> add(Old, Counters) end,
                         Counters, Acc)
    end, #{}, Stats),
    maps:foreach(fun(Type, Counters) -> print(Type, Counters) end, ByType),
    wait(Seconds).

add(A, B) ->
    maps:fold(fun(K, V, Acc) -> maps:update_with(K, fun(X) -> X + V end, V, Acc) end,
              A, B).

print(Type, Counters) ->
    Total = max(1, lists:sum(maps:values(Counters))),
    Parts = [io_lib:format(" ~s=~.1f%", [State, 100 * Time / Total])
             || {State, Time} <- lists:reverse(lists:keysort(2, maps:to_list(Counters))),
                Time > 0],
    io:format("msacc ~s~s~n", [Type, Parts]).
