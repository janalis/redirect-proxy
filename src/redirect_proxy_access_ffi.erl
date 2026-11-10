%% Access log plumbing: one writer per output, value escaping, timestamps
%% and IP anonymisation.
-module(redirect_proxy_access_ffi).

-export([
    start/4, stop/0, sync/0, emit/2, set_levels/2,
    escape_default/1, escape_json/1, escape_newlines/1,
    time_local/1, time_iso8601/1, anonymize_ip/1, anonymize_peer/1,
    now_micros/0, monotonic_micros/0
]).

%% Rendered timestamps of the current second, shared by request processes.
-define(TIME_CACHE, redirect_proxy_access_time).

%% #{Listener => Writer}: where each listener's lines go.
-define(WRITERS, redirect_proxy_access_writers).

%% ---------------------------------------------------------------------------
%% Writers
%% ---------------------------------------------------------------------------

%% Groups: [{Output, [Listener]}] with Output <<"stdout">>, <<"stderr">> or a
%% file path, and Listener an atom (redirect_listener, admin_listener...).
%% One writer (redirect_proxy_access_writer) is started per output.
%% The writers of an earlier start are stopped once the new ones are in
%% place, so that a reload loses no line (and keeps them on an error).
start(Groups, MaxBytes, MaxFiles, Compress) ->
    ensure_time_cache(),
    Previous = persistent_term:get(?WRITERS, #{}),
    case start_groups(Groups, MaxBytes, MaxFiles, Compress, #{}, []) of
        {ok, nil} ->
            stop_writers(Previous),
            {ok, nil};
        Error ->
            Error
    end.

start_groups([], _, _, _, Routes, _) ->
    persistent_term:put(?WRITERS, Routes),
    {ok, nil};
start_groups([{Output, Listeners} | Rest], MaxBytes, MaxFiles, Compress,
             Routes, Started) ->
    case redirect_proxy_access_writer:start(Output, MaxBytes, MaxFiles, Compress) of
        {ok, Writer} ->
            Routes1 = lists:foldl(fun(L, Acc) -> Acc#{L => Writer} end,
                                  Routes, Listeners),
            start_groups(Rest, MaxBytes, MaxFiles, Compress, Routes1,
                         [Writer | Started]);
        {error, Reason} ->
            lists:foreach(fun redirect_proxy_access_writer:stop/1, Started),
            {error, Reason}
    end.

%% Writes what is waiting and stops the writers.
stop() ->
    case persistent_term:get(?WRITERS, none) of
        none ->
            nil;
        Routes ->
            persistent_term:put(?WRITERS, #{}),
            stop_writers(Routes),
            nil
    end.

%% Returns once every writer has handled the lines sent before (tests).
sync() ->
    lists:foreach(fun redirect_proxy_access_writer:sync/1,
                  lists:usort(maps:values(persistent_term:get(?WRITERS, #{})))),
    nil.

stop_writers(Routes) ->
    lists:foreach(fun redirect_proxy_access_writer:stop/1,
                  lists:usort(maps:values(Routes))).

%% A rendered line of Listener's log: a counter and a message, from the
%% request process.
emit(Listener, Line) ->
    case persistent_term:get(?WRITERS, #{}) of
        #{Listener := Writer} -> redirect_proxy_access_writer:send(Writer, Line);
        _ -> ok
    end,
    nil.

%% Primary level and default (application log) handler level.
set_levels(Primary, Default) ->
    logger:set_primary_config(level, Primary),
    _ = logger:set_handler_config(default, level, Default),
    nil.

%% ---------------------------------------------------------------------------
%% Escaping
%% ---------------------------------------------------------------------------

%% nginx `escape=default`: ", \ and bytes outside 0x20..0x7e as \xHH.
escape_default(Bin) ->
    case needs_default_escape(Bin) of
        false -> Bin;
        true -> << <<(escape_byte(C))/binary>> || <<C>> <= Bin >>
    end.

needs_default_escape(<<>>) -> false;
needs_default_escape(<<C, _/binary>>)
  when C < 16#20; C > 16#7e; C =:= $"; C =:= $\\ -> true;
needs_default_escape(<<_, Rest/binary>>) -> needs_default_escape(Rest).

escape_byte(C) when C < 16#20; C > 16#7e; C =:= $"; C =:= $\\ ->
    <<"\\x", (hex(C bsr 4)), (hex(C band 15))>>;
escape_byte(C) -> <<C>>.

hex(N) when N < 10 -> $0 + N;
hex(N) -> $A + N - 10.

%% JSON string contents. Invalid UTF-8 bytes are written as \u00XX so the
%% output is always valid JSON.
escape_json(Bin) -> iolist_to_binary(json_chars(Bin)).

json_chars(<<>>) -> [];
json_chars(<<$", R/binary>>) -> [<<"\\\"">> | json_chars(R)];
json_chars(<<$\\, R/binary>>) -> [<<"\\\\">> | json_chars(R)];
json_chars(<<$\n, R/binary>>) -> [<<"\\n">> | json_chars(R)];
json_chars(<<$\r, R/binary>>) -> [<<"\\r">> | json_chars(R)];
json_chars(<<$\t, R/binary>>) -> [<<"\\t">> | json_chars(R)];
json_chars(<<C, R/binary>>) when C < 16#20 -> [u_escape(C) | json_chars(R)];
%% Valid in JSON, but control or line separator characters for the tools
%% that read logs: DEL, the C1 controls (U+0085 is a line break for some)
%% and the Unicode line and paragraph separators.
json_chars(<<C/utf8, R/binary>>)
  when C =:= 16#7f; C >= 16#80, C =< 16#9f; C =:= 16#2028; C =:= 16#2029 ->
    [u4_escape(C) | json_chars(R)];
json_chars(<<C/utf8, R/binary>>) -> [<<C/utf8>> | json_chars(R)];
json_chars(<<C, R/binary>>) -> [u_escape(C) | json_chars(R)].

u_escape(C) -> <<"\\u00", (hex(C bsr 4)), (hex(C band 15))>>.

u4_escape(C) ->
    <<"\\u", (hex(C bsr 12)), (hex((C bsr 8) band 15)),
      (hex((C bsr 4) band 15)), (hex(C band 15))>>.

escape_newlines(Bin) ->
    binary:replace(binary:replace(Bin, <<"\n">>, <<"\\n">>, [global]),
                   <<"\r">>, <<"\\r">>, [global]).

%% ---------------------------------------------------------------------------
%% Time
%% ---------------------------------------------------------------------------

now_micros() -> erlang:system_time(microsecond).
monotonic_micros() -> erlang:monotonic_time(microsecond).

%% Formatting a timestamp (io_lib:format, local time conversion) costs a
%% few microseconds: it is done once per second and kind, then read from the
%% cache. Without the cache (it is created by start/4), it is done each time.
time_local(Micros) ->
    cached(time_local, Micros div 1000000, fun render_time_local/1).

time_iso8601(Micros) ->
    cached(time_iso8601, Micros div 1000000, fun render_time_iso8601/1).

cached(Kind, Seconds, Render) ->
    try ets:lookup(?TIME_CACHE, Kind) of
        [{_, Seconds, Rendered}] -> Rendered;
        _ ->
            Rendered = Render(Seconds),
            ets:insert(?TIME_CACHE, {Kind, Seconds, Rendered}),
            Rendered
    catch
        error:badarg -> Render(Seconds)
    end.

%% The table belongs to a process that never exits, so that it outlives the
%% process that started the access log.
ensure_time_cache() ->
    case ets:whereis(?TIME_CACHE) of
        undefined ->
            Self = self(),
            Owner = spawn(fun() ->
                try
                    _ = ets:new(?TIME_CACHE, [named_table, public, set,
                                              {read_concurrency, true},
                                              {write_concurrency, true}])
                catch
                    error:badarg -> ok  % created concurrently
                end,
                Self ! {?TIME_CACHE, self()},
                receive after infinity -> ok end
            end),
            receive {?TIME_CACHE, Owner} -> ok after 1000 -> ok end;
        _ -> ok
    end.

%% Common Log Format time: 06/Nov/2026:10:00:00 +0100
render_time_local(Seconds) ->
    {{Y, Mo, D}, {H, Mi, S}} = Local =
        calendar:system_time_to_local_time(Seconds, second),
    Utc = calendar:system_time_to_universal_time(Seconds, second),
    Offset = (calendar:datetime_to_gregorian_seconds(Local)
              - calendar:datetime_to_gregorian_seconds(Utc)) div 60,
    Sign = case Offset < 0 of true -> $-; false -> $+ end,
    Abs = abs(Offset),
    iolist_to_binary(io_lib:format("~2..0B/~s/~4..0B:~2..0B:~2..0B:~2..0B ~c~2..0B~2..0B",
        [D, month(Mo), Y, H, Mi, S, Sign, Abs div 60, Abs rem 60])).

render_time_iso8601(Seconds) ->
    list_to_binary(calendar:system_time_to_rfc3339(Seconds, [{unit, second}])).

month(M) ->
    element(M, {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}).

%% ---------------------------------------------------------------------------
%% IP anonymisation (IPv4 /24, IPv6 /48)
%% ---------------------------------------------------------------------------

anonymize_ip(Bin) ->
    case inet:parse_strict_address(binary_to_list(Bin)) of
        {ok, {A, B, C, _}} ->
            list_to_binary(inet:ntoa({A, B, C, 0}));
        {ok, {0, 0, 0, 0, 0, 16#ffff, AB, CD}} ->
            %% IPv4-mapped IPv6 (dual stack sockets): log as IPv4
            list_to_binary(inet:ntoa({AB bsr 8, AB band 255, CD bsr 8, 0}));
        {ok, {16#2002, B, C, _, _, _, _, _}} ->
            %% 6to4: the /48 holds the client's whole IPv4 address; keep its
            %% /24, as for IPv4
            list_to_binary(inet:ntoa({16#2002, B, C band 16#ff00, 0, 0, 0, 0, 0}));
        {ok, {A, B, C, _, _, _, _, _}} ->
            list_to_binary(inet:ntoa({A, B, C, 0, 0, 0, 0, 0}));
        _ ->
            <<>>
    end.

%% anonymize_ip/1 of a mist peer address ({ip_v4, ...} or {ip_v6, ...}),
%% without formatting then parsing it.
anonymize_peer({ip_v4, A, B, C, _}) ->
    list_to_binary(inet:ntoa({A, B, C, 0}));
anonymize_peer({ip_v6, 0, 0, 0, 0, 0, 16#ffff, AB, CD}) ->
    list_to_binary(inet:ntoa({AB bsr 8, AB band 255, CD bsr 8, 0}));
anonymize_peer({ip_v6, 16#2002, B, C, _, _, _, _, _}) ->
    list_to_binary(inet:ntoa({16#2002, B, C band 16#ff00, 0, 0, 0, 0, 0}));
anonymize_peer({ip_v6, A, B, C, _, _, _, _, _}) ->
    list_to_binary(inet:ntoa({A, B, C, 0, 0, 0, 0, 0})).
