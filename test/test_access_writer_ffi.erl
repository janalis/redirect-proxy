%% Deterministic path replacement between exclusive-open failure and append.
-module(test_access_writer_ffi).
-include_lib("kernel/include/file.hrl").
-export([reopen_race/2, denied_reopen_race/1]).

reopen_race(Dir, Replace) ->
    Path = filename:join(binary_to_list(Dir), "access.log"),
    Replacement = Path ++ ".replacement",
    ok = file:write_file(Path, <<>>),
    ok = file:change_mode(Path, 8#600),
    ok = file:write_file(Replacement, <<>>),
    ok = file:change_mode(Replacement, 8#640),
    race(Path, Replacement, Replace, false),
    nil.

%% The parent harness prepares 0600/0640 files outside the denied process.
denied_reopen_race(Dir) ->
    Path = filename:join(binary_to_list(Dir), "access.log"),
    race(Path, Path ++ ".replacement", false, true),
    nil.

race(Path, Replacement, Replace, Denied) ->
    {ok, W = {Pid, _}} = redirect_proxy_access_writer:start(
        list_to_binary(Path), 0, 1, false),
    Key = {redirect_proxy_access_writer, open_collision_hook},
    Parent = self(),
    Ref = make_ref(),
    Hook = fun(P) ->
        case P =:= Path of
            true ->
                Parent ! {Ref, paused, self()},
                receive {Ref, continue} -> ok after 5000 -> error(barrier_timeout) end;
            false -> ok
        end
    end,
    try
        ok = file:rename(Path, Path ++ ".old"),
        ok = file:rename(Replacement, Path),
        persistent_term:put(Key, Hook),
        Pid ! check,
        receive {Ref, paused, Pid} -> ok after 5000 -> error(no_barrier) end,
        %% Keep the old inode alive: a newly created file cannot reuse it.
        ok = file:rename(Path, Path ++ ".raced"),
        case Replace of
            true ->
                ok = file:write_file(Path, <<>>),
                ok = file:change_mode(Path, 8#644);
            false -> ok
        end,
        _ = persistent_term:erase(Key),
        Pid ! {Ref, continue},
        ok = redirect_proxy_access_writer:sync(W),
        lists:foreach(fun(_) ->
            Pid ! check,
            ok = redirect_proxy_access_writer:sync(W),
            ok = redirect_proxy_access_writer:send(W, <<"private data">>),
            ok = redirect_proxy_access_writer:sync(W)
        end, lists:seq(1, 3)),
        case Denied of
            false ->
                {ok, #file_info{mode = M}} = file:read_file_info(Path),
                8#600 = M band 8#777,
                {ok, <<"private data\nprivate data\nprivate data\n">>} = file:read_file(Path);
            true ->
                %% This uncertain path is not owned: leave it untouched,
                %% but never allow a retry to append private bytes to it.
                {ok, <<>>} = file:read_file(Path)
        end,
        {ok, <<>>} = file:read_file(Path ++ ".raced")
    after
        _ = persistent_term:erase(Key),
        Pid ! {Ref, continue},
        redirect_proxy_access_writer:stop(W)
    end.
