%% Test helper: an unused TCP port on the loopback interface.
-module(test_net_ffi).
-export([cas_regression/0, free_port/0, set_mtime_ago/2, counting_server/0, accepted/1, format_json_log/2,
         raw_exchange/2, session/3, paced_session/4, half_closed/3, reset_after/3, upload/4, parse_outcome/1,
         trickle/3, open/1, send/2, read/2, read_until/3, close/1, connection_process/1, poke/1,
         start_capped/2, hibernated/1, reductions/1, suspend/1, resume/1, queued/1,
         shrink_warned/0, warned_size/0]).

%% The warning timestamps of redirect_proxy_http as an older version of the
%% module left them (two slots), and their size.
shrink_warned() ->
    persistent_term:put({redirect_proxy_http, warned}, atomics:new(2, [])),
    nil.

warned_size() ->
    maps:get(size, atomics:info(persistent_term:get({redirect_proxy_http, warned}))).

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

%% A client connection to 127.0.0.1:Port, driven step by step.
open(Port) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    S.

send(S, Data) ->
    _ = gen_tcp:send(S, Data),
    nil.

%% Reads until the server closes the connection or WaitMs of silence.
%% Returns {Received, Closed}.
read(S, WaitMs) ->
    read_until_closed(S, <<>>, WaitMs).

%% Reads until what was received ends with Suffix, the connection closes,
%% or WaitMs pass without a byte. Returns {Received, Closed}: unlike read/2,
%% it does not wait for a silence once the awaited bytes came, so a test
%% can allow a loaded machine plenty of time at no cost.
read_until(S, Suffix, WaitMs) ->
    read_until(S, Suffix, WaitMs, <<>>).

read_until(S, Suffix, WaitMs, Acc) ->
    N = byte_size(Suffix),
    case byte_size(Acc) >= N andalso binary:part(Acc, byte_size(Acc) - N, N) =:= Suffix of
        true -> {Acc, false};
        false ->
            case gen_tcp:recv(S, 0, WaitMs) of
                {ok, Data} -> read_until(S, Suffix, WaitMs, <<Acc/binary, Data/binary>>);
                {error, closed} -> {Acc, true};
                {error, _} -> {Acc, false}
            end
    end.

close(S) ->
    gen_tcp:close(S),
    nil.

%% The process that serves the client connection S: the owner of the
%% server side socket (the one whose peer is S).
connection_process(S) ->
    {ok, Local} = inet:sockname(S),
    [Pid] = [Pid || P <- erlang:ports(),
                    inet:peername(P) =:= {ok, Local},
                    {connected, Pid} <- [erlang:port_info(P, connected)]],
    Pid.

%% A message the process does not expect.
poke(Pid) ->
    Pid ! stray,
    nil.

%% A redirect listener (idle timeout 300 ms) that serves at most Cap
%% connections at a time. Returns its port.
start_capped(Handler, Cap) ->
    {ok, {started, _, Port}} = redirect_proxy_http:start(
        <<"127.0.0.1">>, 0, Handler, {options, 300, 1024, false, none, 0, {[], []}, Cap}),
    Port.

%% Whether the process is hibernated, without waking it up.
hibernated(Pid) ->
    erlang:process_info(Pid, current_function) =:= {current_function, {erlang, hibernate, 3}}.

%% The reductions of the process so far: they grow whenever it runs.
reductions(Pid) ->
    {reductions, N} = erlang:process_info(Pid, reductions),
    N.

suspend(Pid) ->
    true = erlang:suspend_process(Pid),
    nil.

resume(Pid) ->
    true = erlang:resume_process(Pid),
    nil.

%% The number of messages in the mailbox of the process.
queued(Pid) ->
    {message_queue_len, N} = erlang:process_info(Pid, message_queue_len),
    N.

%% Sends Head and the first part of a body, then the rest in parts GapMs
%% apart (ignoring errors: the server may have closed), as an upload does,
%% then reads until closed. Returns the bytes read, and whether the read
%% ended with a reset rather than a close.
upload(Port, Head, Part, Parts) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port,
                              [binary, {active, false}, {sndbuf, 16384}]),
    ok = gen_tcp:send(S, [Head, Part]),
    lists:foreach(fun(_) ->
        timer:sleep(20),
        _ = gen_tcp:send(S, Part)
    end, lists:seq(1, Parts)),
    upload_read(S, <<>>).

upload_read(S, Acc) ->
    case gen_tcp:recv(S, 0, 3000) of
        {ok, Data} -> upload_read(S, <<Acc/binary, Data/binary>>);
        {error, closed} -> gen_tcp:close(S), {Acc, false};
        {error, _} -> gen_tcp:close(S), {Acc, true}
    end.

%% Exact binary-key lookups and safe fallback for match-spec-shaped keys.
cas_regression() ->
    Table = <<"redirect_proxy_cas_regression">>,
    redirect_proxy_ets_ffi:ets_new(Table),
    lists:foreach(fun(Key) ->
        Old = {'$1', '_'},
        New = {const, '$2'},
        redirect_proxy_ets_ffi:ets_put(Table, Key, Old),
        true = redirect_proxy_ets_ffi:ets_replace_if(Table, Key, Old, New),
        false = redirect_proxy_ets_ffi:ets_replace_if(Table, Key, Old, Old),
        false = redirect_proxy_ets_ffi:ets_delete_if(Table, Key, Old),
        {ok, New} = redirect_proxy_ets_ffi:ets_get(Table, Key),
        true = redirect_proxy_ets_ffi:ets_delete_if(Table, Key, New),
        false = redirect_proxy_ets_ffi:ets_delete_if(Table, Key, New)
    end, [<<"$1">>, <<"_">>, '$1', {'_', '$2'}, 42]),
    Small = cas_reductions(Table, 1),
    Large = cas_reductions(Table, 10000),
    true = Large < Small * 5,
    nil.

cas_reductions(Table, Size) ->
    ets:delete_all_objects(redirect_proxy_cas_regression),
    ets:insert(redirect_proxy_cas_regression,
               [{integer_to_binary(I), old} || I <- lists:seq(1, Size)]),
    {reductions, Before} = process_info(self(), reductions),
    lists:foreach(fun(_) ->
        true = redirect_proxy_ets_ffi:ets_replace_if(Table, <<"1">>, old, old),
        true = redirect_proxy_ets_ffi:ets_delete_if(Table, <<"1">>, old),
        redirect_proxy_ets_ffi:ets_put(Table, <<"1">>, old)
    end, lists:seq(1, 100)),
    {reductions, After} = process_info(self(), reductions),
    After - Before.
