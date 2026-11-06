-module(matcher_bench_ffi).
-export([reductions/1]).

%% The reductions the calling process spends in F.
reductions(F) ->
    {reductions, Before} = process_info(self(), reductions),
    _ = F(),
    {reductions, After} = process_info(self(), reductions),
    After - Before.
