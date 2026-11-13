%% Files: atomic writes, stamps, the node-local and cross-process locks, and
%% the tunables tests shorten.
-module(redirect_proxy_file_ffi).

-export([
    append_line/2, audit_rotate/4, atomic_write/2, atomic_write_private/2, atomic_write_as/3, clear_tunable/1,
    copy_file_as/2, data_dir_owner_mismatch/1, file_stamp/1, memo_file/2,
    probe_writable_file/1,
    same_write/2, set_tunable/2, stamp_is_recent/1, tunable/2,
    with_file_lock/3, with_file_lock_detailed/3, with_lock/2
]).

-include_lib("kernel/include/file.hrl").

%% ---------------------------------------------------------------------------
%% Files
%% ---------------------------------------------------------------------------

%% Tests creating a file without following or deleting an occupied path.
probe_writable_file(Path) ->
    Result = case file:open(Path, [write, exclusive, raw, binary]) of
        {ok, Fd} ->
            Closed = file:close(Fd),
            Deleted = file:delete(Path),
            case Closed of
                ok -> Deleted;
                Error -> Error
            end;
        Error -> Error
    end,
    case Result of
        ok -> {ok, nil};
        {error, Reason} -> {error, atom_to_binary_safe(Reason)}
    end.

atomic_write(Path, Content) -> atomic_write(Path, Content, default).

%% For files holding secrets (password hashes, client secret hashes, the
%% cookie signing key): created 0600 instead of the umask default.
atomic_write_private(Path, Content) -> atomic_write(Path, Content, 8#600).

%% Exact permissions of a source archive, regardless of the destination's
%% previous permissions (or a symlink there). Set before writing bytes.
atomic_write_as(Path, Content, Mode) ->
    atomic_write(Path, Content, {exact, Mode band 8#7777}).

atomic_write(Path, Content, NewMode) ->
    atomic_write(Path, Content, NewMode, fun() -> ok end).

%% Preparation (including chmod and fsync) happens before BeforeRename.
atomic_write(Path, Content, NewMode, BeforeRename) ->
    _ = filelib:ensure_dir(Path),
    Tmp = <<Path/binary, ".tmp.", (integer_to_binary(erlang:unique_integer([positive])))/binary>>,
    %% Every step returns {error, _} instead of raising, so that a full or
    %% failing disk is reported to the caller and the temp file is removed.
    Result =
        case file:open(Tmp, [write, exclusive, raw, binary]) of
            {ok, Fd} ->
                %% before the content is written: a secret is never readable
                %% by others, not even for a moment
                Written = case set_mode(Path, Tmp, NewMode) of
                    ok -> write_and_sync(Fd, Content);
                    ModeError -> ModeError
                end,
                Closed = file:close(Fd),
                WrittenResult = case {Written, Closed} of
                    {ok, ok} ->
                        case BeforeRename() of
                            ok ->
                                case file:rename(Tmp, Path) of
                                    ok -> sync_dir(filename:dirname(Path));
                                    RenameError -> RenameError
                                end;
                            BeforeError -> BeforeError
                        end;
                    {ok, CloseError} -> CloseError;
                    {WriteError, _} -> WriteError
                end,
                %% Only this successful exclusive open owns Tmp. Never
                %% remove a conflicting file or symlink on open failure.
                case WrittenResult of
                    ok -> ok;
                    _ -> _ = file:delete(Tmp), WrittenResult
                end;
            Error -> Error
        end,
    case Result of
        ok -> {ok, nil};
        {error, Reason} ->
            {error, atom_to_binary_safe(Reason)}
    end.

%% Prepare the next audit entry without retiring the current active file.
%% Archive it only after the replacement is ready, and then replace it
%% atomically: failures never leave an absent active file with a lost mode.
audit_rotate(Path, Line, Mode, Keep) ->
    atomic_write(Path, [Line, $\n], {exact, Mode band 8#7777}, fun() ->
        audit_backups(Path, Keep)
    end).

audit_backups(_, 0) -> ok;
audit_backups(Path, Keep) ->
    case optional_file_result(file:delete(audit_archive(Path, Keep))) of
        ok ->
            case audit_shift(Path, Keep - 1) of
                ok ->
                    case copy_file_as(Path, audit_archive(Path, 1)) of
                        {ok, nil} -> ok;
                        {error, Reason} -> {error, Reason}
                    end;
                Error -> Error
            end;
        Error -> Error
    end.

audit_shift(_, 0) -> ok;
audit_shift(Path, N) ->
    case optional_file_result(file:rename(audit_archive(Path, N),
                                          audit_archive(Path, N + 1))) of
        ok -> audit_shift(Path, N - 1);
        Error -> Error
    end.

audit_archive(Path, N) ->
    <<Path/binary, ".", (integer_to_binary(N))/binary>>.

optional_file_result({error, enoent}) -> ok;
optional_file_result(Result) -> Result.

%% The new file replaces the old one: give it the old one's permissions
%% (e.g. 0640 for a group-readable redirections file) instead of the umask
%% default. A new file gets NewMode, or the umask default. A private file
%% (with a NewMode) is never readable by others: its group may have been
%% given access on purpose, the rest of the system never is.
set_mode(_, Tmp, {exact, Mode}) ->
    file:change_mode(Tmp, Mode);
set_mode(Path, Tmp, NewMode) ->
    case {file:read_file_info(Path), NewMode} of
        {{ok, #file_info{mode = Mode}}, default} -> file:change_mode(Tmp, Mode band 8#7777);
        {{ok, #file_info{mode = Mode}}, _} -> file:change_mode(Tmp, Mode band 8#7770);
        {{error, _}, default} -> ok;
        {{error, _}, _} -> file:change_mode(Tmp, NewMode)
    end.

%% Copies Source to a new file Dest that has Source's permissions before it
%% holds any of its bytes (a copy then a chmod leaves the copy readable with
%% the umask default for a moment).
copy_file_as(Source, Dest) ->
    Result =
        case file:read_file_info(Source) of
            {ok, #file_info{mode = Mode}} ->
                case file:open(Dest, [write, exclusive, raw, binary]) of
                    {ok, Fd} ->
                        %% written through the open descriptor: a mode
                        %% without the owner's write bit (a read-only
                        %% rules file) does not apply to it
                        Copied = case file:change_mode(Dest, Mode band 8#7777) of
                            ok -> file:copy(Source, Fd);
                            ModeError -> ModeError
                        end,
                        Closed = file:close(Fd),
                        case {Copied, Closed} of
                            {{ok, _}, ok} ->
                                ok;
                            {_, _} ->
                                %% no partial backup left behind
                                _ = file:delete(Dest),
                                case Copied of
                                    {ok, _} -> Closed;
                                    CopyError -> CopyError
                                end
                        end;
                    OpenError ->
                        OpenError
                end;
            InfoError ->
                InfoError
        end,
    case Result of
        ok -> {ok, nil};
        {error, Reason} -> {error, atom_to_binary_safe(Reason)}
    end.

%% Makes the rename durable: without it, a power loss right after a write
%% can bring the old file back. Best effort: a file system that cannot open
%% or sync a directory leaves the rename as it is.
sync_dir(Dir) ->
    case file:open(Dir, [read, raw, directory]) of
        {ok, Fd} ->
            _ = file:sync(Fd),
            _ = file:close(Fd),
            ok;
        {error, _} -> ok
    end.

write_and_sync(Fd, Content) ->
    case file:write(Fd, Content) of
        ok -> file:sync(Fd);
        Error -> Error
    end.

append_line(Path, Line) ->
    case file:write_file(Path, [Line, $\n], [append, raw]) of
        ok -> {ok, nil};
        {error, Reason} -> {error, atom_to_binary_safe(Reason)}
    end.

%% Fun() computed from a file, cached until the file changes. Writes replace
%% the file (atomic_write renames a new one), so the inode tells versions
%% apart even within the second of mtime. When Fun() fails, the last good
%% value is kept (a corrupt or half-written file does not break readers).
%% Changes when a file is replaced (inode), written (mtime) or resized.
file_stamp(Path) ->
    case file:read_file_info(Path, [{time, posix}]) of
        {ok, #file_info{inode = Inode, mtime = MTime, size = Size}} ->
            {Inode, MTime, Size};
        {error, _} -> missing
    end.

%% Whether stamp B may be of the write of stamp A: the same file (inode)
%% and size, its time moved forward by a second at most (a write in place
%% may set it again after the content). Times have a one second
%% resolution: the same content written again within that second cannot
%% be told apart from it.
same_write({Inode, MTimeA, Size}, {Inode, MTimeB, Size}) ->
    MTimeB >= MTimeA andalso MTimeB - MTimeA =< 1;
same_write(_, _) -> false.

%% Whether a stamp's modification time is within the last two seconds:
%% another write in that same second would leave the stamp as it is (the
%% time has a one second resolution) when it keeps the size and the inode.
stamp_is_recent({_, MTime, _}) -> MTime >= os:system_time(second) - 2;
stamp_is_recent(missing) -> false.

memo_file(Path, Fun) ->
    Stamp = file_stamp(Path),
    Table = memo_table(),
    Cached = try ets:lookup(Table, Path) catch error:badarg -> [] end,
    Recent = stamp_is_recent(Stamp),
    case Cached of
        [{_, Stamp, Value}] when not Recent -> Value;
        _ ->
            case Fun() of
                {ok, _} = Ok ->
                    try ets:insert(Table, {Path, Stamp, Ok})
                    catch error:badarg -> ok
                    end,
                    Ok;
                Error ->
                    case Cached of
                        [{_, _, {ok, _} = Last}] -> Last;
                        _ -> Error
                    end
            end
    end.

memo_table() ->
    case ets:whereis(redirect_proxy_memo) of
        undefined ->
            Self = self(),
            Owner = spawn(fun() ->
                try ets:new(redirect_proxy_memo, [named_table, public, set,
                                                  {read_concurrency, true}])
                catch error:badarg -> ok  % created concurrently
                end,
                Self ! {redirect_proxy_memo, self()},
                receive after infinity -> ok end
            end),
            receive {redirect_proxy_memo, Owner} -> ok after 1000 -> ok end;
        _ -> ok
    end,
    redirect_proxy_memo.

atom_to_binary_safe(A) when is_atom(A) -> atom_to_binary(A);
atom_to_binary_safe(T) -> unicode:characters_to_binary(io_lib:format("~p", [T])).

%% ---------------------------------------------------------------------------
%% Node-local mutual exclusion
%% ---------------------------------------------------------------------------

with_lock(Name, Fun) ->
    global:trans({{redirect_proxy, Name}, self()}, Fun, [node()], infinity).

%% ---------------------------------------------------------------------------
%% Cross-process file lock (<Path>.lock, created with O_EXCL)
%% ---------------------------------------------------------------------------

%% A lock not refreshed for this long is left over by a crashed process: its
%% holder refreshes it while it runs (`start_lock_refresher`).
-define(STALE_LOCK_SECONDS, 10).

%% A delay that tests shorten (`set_tunable`): read where a lock is judged
%% stale or a store call starts, never on the request path.
tunable(Name, Default) ->
    persistent_term:get({?MODULE, tunable, Name}, Default).

set_tunable(Name, Value) ->
    persistent_term:put({?MODULE, tunable, Name}, Value),
    nil.

clear_tunable(Name) ->
    _ = persistent_term:erase({?MODULE, tunable, Name}),
    nil.

%% Runs Fun while holding <Path>.lock, shared by every OS process (server,
%% CLI) that writes Path. Returns {ok, Result} or {error, Reason} when the
%% lock is not acquired within TimeoutMs.
%%
%% The lock file holds a token unique to this acquisition, so that a holder
%% only ever removes its own lock: when it was held past the stale delay and
%% another process broke it, releasing leaves the new owner's lock in place.
with_file_lock(Path, TimeoutMs, Fun) ->
    case with_file_lock_detailed(Path, TimeoutMs, Fun) of
        {error, {_, Message}} -> {error, Message};
        Result -> Result
    end.

%% with_file_lock/3, failing with {held, Message} (another process holds
%% the lock) or {cannot_create, Message} (a full disk...).
with_file_lock_detailed(Path, TimeoutMs, Fun) ->
    Lock = <<Path/binary, ".lock">>,
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    %% the data directory may not exist yet (first CLI command)
    _ = filelib:ensure_dir(Lock),
    Token = lock_token(),
    case acquire_lock(Lock, Token, Deadline) of
        ok ->
            Refresher = start_lock_refresher(Lock, Token),
            try {ok, Fun()}
            after
                stop_lock_refresher(Refresher),
                release_lock(Lock, Token)
            end;
        %% A directory this process cannot create files in is one it cannot
        %% write the rules to either (writes are a temp file and a rename):
        %% a replica reading a read-only volume. Run without the lock; the
        %% writers of other processes replace the file atomically.
        read_only ->
            {ok, Fun()};
        {error, Reason} ->
            {error, Reason}
    end.

lock_token() ->
    iolist_to_binary(io_lib:format("~s ~s ~B~n",
        [os:getpid(), node(), erlang:unique_integer([positive])])).

acquire_lock(Lock, Token, Deadline) ->
    case file:open(Lock, [write, exclusive, raw, binary]) of
        {ok, Fd} ->
            Written = file:write(Fd, Token),
            _ = file:close(Fd),
            case Written of
                ok -> ok;
                {error, Reason} ->
                    %% an empty lock would never be released by its token
                    _ = file:delete(Lock),
                    {error, {cannot_create, <<"cannot write ", Lock/binary, ": ",
                              (atom_to_binary_safe(Reason))/binary>>}}
            end;
        {error, Read} when Read =:= eacces; Read =:= erofs; Read =:= eperm ->
            read_only;
        {error, eexist} ->
            case break_stale_lock(Lock) of
                true -> acquire_lock(Lock, Token, Deadline);
                false ->
                    case erlang:monotonic_time(millisecond) >= Deadline of
                        true ->
                            {error, {held, <<Lock/binary, " is held by another process (",
                                      (lock_owner(Lock))/binary, ")">>}};
                        false ->
                            timer:sleep(5 + rand:uniform(20)),
                            acquire_lock(Lock, Token, Deadline)
                    end
            end;
        {error, Reason} ->
            {error, {cannot_create, <<"cannot create ", Lock/binary, ": ",
                      (atom_to_binary_safe(Reason))/binary>>}}
    end.

%% Removes a stale lock and returns true when the caller should retry at
%% once. Several waiters may see the same stale lock: breaking it holds
%% <Lock>.break (created with O_EXCL) and checks again that the lock is
%% stale, so a waiter never deletes the fresh lock another one just took.
break_stale_lock(Lock) ->
    case is_stale_file(Lock) of
        false -> false;
        true ->
            Breaker = <<Lock/binary, ".break">>,
            case file:open(Breaker, [write, exclusive, raw]) of
                {ok, Fd} ->
                    _ = file:close(Fd),
                    _ = case is_stale_file(Lock) of
                        true -> file:delete(Lock);
                        false -> ok
                    end,
                    _ = file:delete(Breaker),
                    true;
                {error, _} ->
                    %% another waiter is breaking it (held for microseconds):
                    %% a breaker left by a crash is removed in turn
                    _ = case is_stale_file(Breaker) of
                        true -> file:delete(Breaker);
                        false -> ok
                    end,
                    false
            end
    end.

%% While the lock is held (a matcher build, fsyncs and the audit may take
%% longer than the stale delay on a large rule set), a linked process sets
%% its modification time to now, five times per stale delay, so that no
%% waiter takes it over. It dies with the holder.
start_lock_refresher(Lock, Token) ->
    Interval = max(100, stale_lock_seconds() * 200),
    spawn_link(fun() -> refresh_lock(Lock, Token, Interval) end).

stop_lock_refresher(Refresher) ->
    unlink(Refresher),
    exit(Refresher, kill),
    ok.

refresh_lock(Lock, Token, Interval) ->
    receive after Interval -> ok end,
    %% only this acquisition's lock: never one taken over meanwhile
    _ = case file:read_file(Lock) of
        {ok, Token} ->
            Now = os:system_time(second),
            file:write_file_info(Lock, #file_info{atime = Now, mtime = Now},
                                 [{time, posix}]);
        _ -> ok
    end,
    refresh_lock(Lock, Token, Interval).

%% Releases the lock only while it still holds this acquisition's token.
release_lock(Lock, Token) ->
    case file:read_file(Lock) of
        {ok, Token} -> _ = file:delete(Lock), ok;
        _ -> ok
    end.

%% File times come from the OS clock: compared with it, not with the VM's
%% system time, which lags or leads it after the OS clock is stepped (no
%% time warp), and would then take a fresh lock for a stale one.
is_stale_file(Path) ->
    case file:read_file_info(Path, [{time, posix}]) of
        {ok, {file_info, _, _, _, _, MTime, _, _, _, _, _, _, _, _}} ->
            MTime < os:system_time(second) - stale_lock_seconds();
        _ -> false
    end.

stale_lock_seconds() ->
    tunable(<<"stale_lock_seconds">>, ?STALE_LOCK_SECONDS).

lock_owner(Lock) ->
    case file:read_file(Lock) of
        {ok, Content} -> string:trim(Content);
        _ -> <<"unknown">>
    end.

%% When the calling OS process runs as root and Dir belongs to another
%% user: {ok, OwnerName}. Otherwise (or when it cannot be told) error.
data_dir_owner_mismatch(Dir) ->
    Uid = string:trim(os:cmd("id -u")),
    case {Uid, file:read_file_info(Dir)} of
        {"0", {ok, #file_info{uid = Owner}}} when Owner =/= 0 ->
            Name = string:trim(os:cmd("id -nu " ++ integer_to_list(Owner) ++ " 2>/dev/null")),
            {ok, unicode:characters_to_binary(case Name of
                "" -> integer_to_list(Owner);
                _ -> Name
            end)};
        _ -> {error, nil}
    end.
