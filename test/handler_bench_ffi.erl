-module(handler_bench_ffi).
-export([best_ns/3, reductions/2, parse/1, profile/1]).

%% Best average over Rounds runs of N calls, in ns per call.
best_ns(F, N, Rounds) ->
    lists:min([run(F, N) || _ <- lists:seq(1, Rounds)]).

run(F, N) ->
    erlang:garbage_collect(),
    T0 = erlang:monotonic_time(nanosecond),
    loop(F, N),
    (erlang:monotonic_time(nanosecond) - T0) div N.

loop(_, 0) -> ok;
loop(F, N) -> _ = F(), loop(F, N - 1).

%% Reductions per call.
reductions(F, N) ->
    {reductions, Before} = process_info(self(), reductions),
    loop(F, N),
    {reductions, After} = process_info(self(), reductions),
    (After - Before) div N.

parse(Head) ->
    {ok, Request, _, _, _} = redirect_proxy_http:parse(Head),
    Request.

profile(F) ->
    case os:getenv("PROF") of
        false -> nil;
        _ -> tprof:profile(fun() -> loop(F, 100000) end, #{type => call_time}), nil
    end.
