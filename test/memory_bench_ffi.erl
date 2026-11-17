-module(memory_bench_ffi).
-export([flat_words/1, process_memory/1, total_memory/0, binary_memory/0,
         persistent_term_memory/0, gc_all/0]).

flat_words(T) -> erts_debug:flat_size(T).

process_memory(Pid) ->
    erlang:garbage_collect(Pid),
    {memory, M} = erlang:process_info(Pid, memory),
    M.

gc_all() -> [erlang:garbage_collect(P) || P <- erlang:processes()], nil.

total_memory() -> erlang:memory(total).

binary_memory() -> erlang:memory(binary).

persistent_term_memory() -> maps:get(memory, persistent_term:info()).
