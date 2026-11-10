%% One access log output (stdout, stderr or a file): a process that request
%% processes send their rendered lines to, and that writes them in batches.
%%
%% A request process only increments a counter and sends a message: the
%% `logger` front end (level checks, metadata, every handler's filters, the
%% formatter) cost several times the rest of a logged redirect. Like the
%% `logger_std_h` handlers it replaces, a writer never blocks requests: past
%% ?MAX_QUEUED lines waiting, lines are dropped and the drop is reported
%% once a second. It keeps their file behaviour too: a file renamed or
%% removed (logrotate) is reopened within a second, and the built-in
%% rotation names archives `File.0` (newest) to `File.<max_files - 1>`,
%% gzipped as `File.N.gz` with `compress`.
-module(redirect_proxy_access_writer).

-export([start/4, stop/1, send/2, sync/1, init/5]).

-include_lib("kernel/include/file.hrl").

%% lines waiting to be written past which new ones are dropped
-define(MAX_QUEUED, 10000).
%% lines taken from the mailbox for one write
-define(MAX_BATCH, 1000).
%% file check (renamed, removed) and drop report interval
-define(CHECK_MS, 1000).

%% Counter slots
-define(QUEUED, 1).
-define(DROPPED, 2).

-record(w, {
    output,
    %% standard_io | standard_error | {file, Path}
    type,
    fd = none,
    inode = none,
    size = 0,
    max_bytes,
    max_files,
    compress,
    counter
}).

%% {ok, {Pid, Counter}} | {error, Reason}. The writer is not linked to the
%% caller: it lives until stop/1.
start(Output, MaxBytes, MaxFiles, Compress) ->
    Counter = atomics:new(2, []),
    case proc_lib:start(?MODULE, init,
                        [self(), Output, {MaxBytes, MaxFiles, Compress},
                         Counter, group_leader()]) of
        {ok, Pid} -> {ok, {Pid, Counter}};
        {error, Reason} -> {error, Reason}
    end.

%% Writes what is waiting, closes the output and ends the writer. Waits
%% for it up to 5 seconds; a writer still busy then (compressing a large
%% archive) finishes on its own.
stop({Pid, _}) ->
    call(Pid, stop, 5000).

%% Returns once the writer has handled every line sent before (tests).
sync({Pid, _}) ->
    call(Pid, sync, 5000).

call(Pid, Request, Timeout) ->
    Ref = monitor(process, Pid),
    Pid ! {Request, self(), Ref},
    receive
        {Ref, done} -> demonitor(Ref, [flush]), ok;
        {'DOWN', Ref, process, Pid, _} -> ok
    after Timeout ->
        demonitor(Ref, [flush]),
        ok
    end.

%% From a request process: queues Line (without its line break).
send({Pid, Counter}, Line) ->
    case atomics:add_get(Counter, ?QUEUED, 1) > ?MAX_QUEUED of
        true ->
            atomics:sub(Counter, ?QUEUED, 1),
            atomics:add(Counter, ?DROPPED, 1);
        false ->
            Pid ! {line, Line}
    end,
    ok.

init(Parent, Output, {MaxBytes, MaxFiles, Compress}, Counter, GroupLeader) ->
    %% stdout and stderr are the caller's: the writer has no other
    group_leader(GroupLeader, self()),
    W0 = #w{output = Output, max_bytes = MaxBytes, max_files = MaxFiles,
            compress = Compress, counter = Counter},
    case output_type(Output) of
        {ok, Type} ->
            case open(W0#w{type = Type}) of
                {ok, W} ->
                    proc_lib:init_ack(Parent, {ok, self()}),
                    erlang:send_after(?CHECK_MS, self(), check),
                    loop(W);
                {error, Reason} ->
                    proc_lib:init_ack(Parent, {error, describe(Output, Reason)})
            end;
        {error, Reason} ->
            proc_lib:init_ack(Parent, {error, describe(Output, Reason)})
    end.

output_type(<<"stdout">>) -> {ok, standard_io};
output_type(<<"stderr">>) -> {ok, standard_error};
output_type(Path) ->
    Name = unicode:characters_to_list(Path),
    case filelib:ensure_dir(Name) of
        ok -> {ok, {file, Name}};
        {error, Reason} -> {error, Reason}
    end.

describe(Output, Reason) ->
    unicode:characters_to_binary(
        io_lib:format("cannot open access log ~ts: ~p", [Output, Reason])).

loop(W) ->
    receive
        {line, Line} ->
            {Lines, N} = take([[Line, $\n]], 1),
            atomics:sub(W#w.counter, ?QUEUED, N),
            loop(safely(fun() -> write(lists:reverse(Lines), N, W) end, W));
        check ->
            report_dropped(W),
            erlang:send_after(?CHECK_MS, self(), check),
            loop(safely(fun() -> reopen_if_moved(W) end, W));
        {sync, From, Ref} ->
            From ! {Ref, done},
            loop(W);
        {stop, From, Ref} ->
            W1 = drain(W),
            report_dropped(W1),
            close(W1),
            From ! {Ref, done};
        _ ->
            loop(W)
    end.

%% Every line waiting, in batches.
drain(W) ->
    case take([], 0) of
        {[], 0} ->
            W;
        {Lines, N} ->
            atomics:sub(W#w.counter, ?QUEUED, N),
            drain(safely(fun() -> write(lists:reverse(Lines), N, W) end, W))
    end.

%% A writer that dies loses every line after it, without a report: an
%% unexpected error is logged and the writer goes on.
safely(Fun, W) ->
    try
        Fun()
    catch
        Class:Reason:Stack ->
            logger:error("access log ~ts: ~p",
                         [W#w.output, {Class, Reason, Stack}]),
            W
    end.

%% The lines already waiting, up to ?MAX_BATCH in all, newest first.
take(Lines, N) when N >= ?MAX_BATCH ->
    {Lines, N};
take(Lines, N) ->
    receive
        {line, Line} -> take([[Line, $\n] | Lines], N + 1)
    after 0 ->
        {Lines, N}
    end.

%% N lines. Lines that cannot be written (no open file, a write error)
%% are reported as dropped.
write([], _, W) ->
    W;
write(_, N, #w{type = {file, _}, fd = none} = W) ->
    atomics:add(W#w.counter, ?DROPPED, N),
    W;
write(Data, N, #w{type = {file, _}, fd = Fd} = W) ->
    case file:write(Fd, Data) of
        ok ->
            maybe_rotate(W#w{size = W#w.size + iolist_size(Data)});
        {error, _} ->
            atomics:add(W#w.counter, ?DROPPED, N),
            W
    end;
write(Data, _, #w{type = Device} = W) ->
    try io:put_chars(Device, Data) catch _:_ -> ok end,
    W.

report_dropped(#w{counter = Counter, output = Output}) ->
    case atomics:exchange(Counter, ?DROPPED, 0) of
        0 -> ok;
        N ->
            logger:warning("access log ~ts: ~B lines dropped (too many waiting, "
                           "or the output cannot be written)", [Output, N])
    end.

%% --- files ------------------------------------------------------------------

open(#w{type = {file, Path}} = W) ->
    %% the directory too may have been removed
    _ = filelib:ensure_dir(Path),
    case file:open(Path, [append, raw, binary]) of
        {ok, Fd} ->
            {Inode, Size} = case file:read_file_info(Path, [raw]) of
                {ok, #file_info{inode = I, size = S}} -> {I, S};
                _ -> {none, 0}
            end,
            {ok, W#w{fd = Fd, inode = Inode, size = Size}};
        {error, Reason} ->
            {error, Reason}
    end;
open(W) ->
    {ok, W}.

close(#w{fd = none}) -> ok;
close(#w{fd = Fd}) -> _ = file:close(Fd), ok.

%% A file renamed or removed (by logrotate, or by hand) is reopened, so that
%% lines go to the file of that name again.
reopen_if_moved(#w{type = {file, Path}, inode = Inode} = W) ->
    case file:read_file_info(Path, [raw]) of
        {ok, #file_info{inode = Inode}} when W#w.fd =/= none ->
            W;
        _ ->
            close(W),
            case open(W#w{fd = none}) of
                {ok, W1} -> W1;
                {error, _} -> W#w{fd = none, inode = none}
            end
    end;
reopen_if_moved(W) ->
    W.

maybe_rotate(#w{max_bytes = Max, size = Size} = W) when Max > 0, Size > Max ->
    rotate(W);
maybe_rotate(W) ->
    W.

rotate(#w{type = {file, Path}, max_files = Count, compress = Compress} = W) ->
    close(W),
    try
        rotate_files(Path, Count, Compress)
    catch
        Class:Reason ->
            logger:warning("access log ~ts: rotation failed: ~p",
                           [W#w.output, {Class, Reason}])
    end,
    case open(W#w{fd = none, size = 0}) of
        {ok, W1} -> W1;
        {error, _} -> W#w{fd = none, inode = none, size = 0}
    end.

%% Path.(Count - 2) -> Path.(Count - 1), ..., Path -> Path.0 (then gzipped
%% with compress): as logger_std_h names them.
rotate_files(Path, 0, _) ->
    _ = file:delete(Path),
    ok;
rotate_files(Path, 1, Compress) ->
    Archive = Path ++ ".0",
    case file:rename(Path, Archive) of
        ok when Compress -> compress_file(Archive);
        _ -> ok
    end;
rotate_files(Path, Count, Compress) ->
    _ = file:rename(archive_name(Path, Count - 2, Compress),
                    archive_name(Path, Count - 1, Compress)),
    rotate_files(Path, Count - 1, Compress).

archive_name(Path, N, false) -> Path ++ "." ++ integer_to_list(N);
archive_name(Path, N, true) -> archive_name(Path, N, false) ++ ".gz".

compress_file(Path) ->
    case file:read_file(Path) of
        {ok, Data} ->
            case file:write_file(Path ++ ".gz", zlib:gzip(Data)) of
                ok -> _ = file:delete(Path), ok;
                _ -> ok
            end;
        _ ->
            ok
    end.
