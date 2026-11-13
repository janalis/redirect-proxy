#!/usr/bin/env escript
%%! +S 1 -noshell
%% Regression for conflicting atomic-write temporary paths, in a fresh VM.
-mode(compile).
-include_lib("kernel/include/file.hrl").

main(_) ->
    true = code:add_patha("build/dev/erlang/redirect_proxy/ebin"),
    {module, redirect_proxy_file_ffi} = code:ensure_loaded(redirect_proxy_file_ffi),
    Base = case os:getenv("TMPDIR") of false -> "/tmp"; D -> D end,
    Dir = filename:join(Base, "rp-atomic-test-" ++ os:getpid()),
    ok = file:make_dir(Dir),
    try
        lists:foreach(fun({Kind, Private}) -> check(Dir, Kind, Private) end,
                      [{regular, false}, {symlink, false},
                       {regular, true}, {symlink, true}]),
        io:format("atomic-write collision tests passed~n")
    after
        {ok, Files} = file:list_dir(Dir),
        lists:foreach(fun(F) -> file:delete(filename:join(Dir, F)) end, Files),
        ok = file:del_dir(Dir)
    end.

check(Dir, Kind, Private) ->
    Path = list_to_binary(filename:join(Dir, "data")),
    Victim = list_to_binary(filename:join(Dir, "sentinel")),
    ok = file:write_file(Path, <<"original">>),
    ok = file:write_file(Victim, <<"untouched">>),
    ok = file:change_mode(Victim, 8#640),
    %% On a single scheduler, cover the next generated positive integer,
    %% including incidental runtime allocations before the open.
    N = erlang:unique_integer([positive]),
    Paths = [<<Path/binary, ".tmp.", (integer_to_binary(I))/binary>>
             || I <- lists:seq(N + 1, N + 1024)],
    lists:foreach(fun(P) ->
        case Kind of
            regular -> ok = file:write_file(P, <<"occupied">>),
                       ok = file:change_mode(P, 8#640);
            symlink -> ok = file:make_symlink(Victim, P)
        end
    end, Paths),
    Write = case Private of
        true -> fun redirect_proxy_file_ffi:atomic_write_private/2;
        false -> fun redirect_proxy_file_ffi:atomic_write/2
    end,
    {error, <<"eexist">>} = Write(Path, <<"replacement">>),
    {ok, <<"original">>} = file:read_file(Path),
    {ok, <<"untouched">>} = file:read_file(Victim),
    {ok, #file_info{mode = Mode}} = file:read_file_info(Victim),
    8#640 = Mode band 8#777,
    lists:foreach(fun(P) ->
        case Kind of
            regular ->
                {ok, <<"occupied">>} = file:read_file(P),
                {ok, #file_info{mode = M}} = file:read_file_info(P),
                8#640 = M band 8#777;
            symlink -> {ok, _} = file:read_link(P)
        end,
        ok = file:delete(P)
    end, Paths).
