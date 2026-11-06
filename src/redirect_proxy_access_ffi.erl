%% Access log plumbing: a dedicated logger_std_h handler, value escaping,
%% timestamps and IP anonymisation.
-module(redirect_proxy_access_ffi).

-export([
    start/4, stop/0, emit/2, format/2, filter/2, set_levels/2,
    escape_default/1, escape_json/1, escape_newlines/1,
    time_local/1, time_iso8601/1, anonymize_ip/1, anonymize_peer/1,
    now_micros/0, monotonic_micros/0
]).

-define(DOMAIN, [redirect_proxy, access]).

%% Rendered timestamps of the current second, shared by request processes.
-define(TIME_CACHE, redirect_proxy_access_time).

%% ---------------------------------------------------------------------------
%% Handlers
%% ---------------------------------------------------------------------------

%% Groups: [{Output, [Listener]}] with Output <<"stdout">>, <<"stderr">> or a
%% file path, and Listener an atom (redirect_listener, admin_listener...).
%% One logger_std_h handler is installed per output.
start(Groups, MaxBytes, MaxFiles, Compress) ->
    _ = stop(),
    ensure_time_cache(),
    keep_out_of_default_handler(),
    let_info_events_through(),
    start_groups(Groups, 1, MaxBytes, MaxFiles, Compress).

start_groups([], _N, _MaxBytes, _MaxFiles, _Compress) ->
    {ok, nil};
start_groups([{Output, Listeners} | Rest], N, MaxBytes, MaxFiles, Compress) ->
    case add_handler(handler_id(N), Output, Listeners, MaxBytes, MaxFiles, Compress) of
        {ok, nil} -> start_groups(Rest, N + 1, MaxBytes, MaxFiles, Compress);
        Error -> _ = stop(), Error
    end.

handler_id(N) -> list_to_atom("redirect_proxy_access_" ++ integer_to_list(N)).

add_handler(Id, Output, Listeners, MaxBytes, MaxFiles, Compress) ->
    case handler_type(Output) of
        {error, Reason} ->
            {error, Reason};
        {ok, Type} ->
            Rotation = case Type of
                {file, _} ->
                    #{max_no_bytes => case MaxBytes of 0 -> infinity; N -> N end,
                      max_no_files => MaxFiles,
                      compress_on_rotate => Compress,
                      %% batch writes, but flush at least twice a second
                      modes => [raw, append, {delayed_write, 65536, 500}],
                      %% reopen the file when it was renamed (logrotate)
                      file_check => 1000};
                _ -> #{}
            end,
            Config = #{
                level => all,
                filter_default => stop,
                filters => [{access, {fun ?MODULE:filter/2, Listeners}}],
                formatter => {?MODULE, #{}},
                config => Rotation#{
                    type => Type,
                    %% Never make request processes wait for the log and
                    %% never throttle it: under extreme overload lines are
                    %% dropped (and the drop is reported) instead.
                    burst_limit_enable => false,
                    sync_mode_qlen => 10000,
                    drop_mode_qlen => 10000,
                    flush_qlen => 20000,
                    overload_kill_enable => false
                }
            },
            case logger:add_handler(Id, logger_std_h, Config) of
                ok -> {ok, nil};
                {error, Error} -> {error, describe(Output, Error)}
            end
    end.

%% Handler filter: only the access events of this handler's listeners.
filter(#{meta := #{domain := [redirect_proxy, access, Listener]}} = Event,
       Listeners) ->
    case lists:member(Listener, Listeners) of
        true -> Event;
        false -> stop
    end;
filter(_Event, _Listeners) ->
    stop.

handler_type(<<"stdout">>) -> {ok, standard_io};
handler_type(<<"stderr">>) -> {ok, standard_error};
handler_type(Path) ->
    case filelib:ensure_dir(Path) of
        ok -> {ok, {file, unicode:characters_to_list(Path)}};
        {error, Reason} -> {error, describe(Path, Reason)}
    end.

describe(Output, Reason) ->
    unicode:characters_to_binary(
        io_lib:format("cannot open access log ~ts: ~p", [Output, Reason])).

stop() ->
    [logger:remove_handler(Id) || Id <- logger:get_handler_ids(),
                                  is_access_handler(Id)],
    nil.

is_access_handler(Id) ->
    lists:prefix("redirect_proxy_access_", atom_to_list(Id)).

keep_out_of_default_handler() ->
    _ = logger:add_handler_filter(default, redirect_proxy_access,
            {fun logger_filters:domain/2, {stop, sub, ?DOMAIN}}),
    ok.

%% Access events are emitted at `info`. When the primary level is stricter
%% (the application log level was set on it), move that level to the default
%% handler so the application log is unchanged, and let `info` through.
let_info_events_through() ->
    #{level := Primary} = logger:get_primary_config(),
    case Primary =/= all andalso Primary =/= none
         andalso logger:compare_levels(Primary, info) =:= gt of
        false -> ok;
        true ->
            case logger:get_handler_config(default) of
                {ok, #{level := Default}} ->
                    Stricter = case Default =:= all orelse
                                    logger:compare_levels(Primary, Default) =:= gt of
                        true -> Primary;
                        false -> Default
                    end,
                    _ = logger:set_handler_config(default, level, Stricter);
                _ -> ok
            end,
            logger:set_primary_config(level, info)
    end.

emit(Listener, Line) ->
    logger:log(info, Line, #{domain => [redirect_proxy, access, Listener]}),
    nil.

%% logger formatter: the line is rendered by the request process already.
format(#{msg := {string, Line}}, _Config) -> [Line, $\n];
format(_Event, _Config) -> [].

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
json_chars(<<C/utf8, R/binary>>) -> [<<C/utf8>> | json_chars(R)];
json_chars(<<C, R/binary>>) -> [u_escape(C) | json_chars(R)].

u_escape(C) -> <<"\\u00", (hex(C bsr 4)), (hex(C band 15))>>.

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
anonymize_peer({ip_v6, A, B, C, _, _, _, _, _}) ->
    list_to_binary(inet:ntoa({A, B, C, 0, 0, 0, 0, 0})).
