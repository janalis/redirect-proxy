%% Time, signals, CLI helpers, runtime metrics, and error rescue.
-module(redirect_proxy_system_ffi).

-export([
    app_version/0, garbage_collect/0, halt/1, memory_bytes/0,
    now_millis/0, now_seconds/0, on_sighup/1, parse_rfc3339/1,
    plain_arguments/0, process_count/0, read_password/1, rescue/1,
    rescue_store_timeout/2, rfc3339/1, start_time_seconds/0, store_timeout/0
]).

%% ---------------------------------------------------------------------------
%% Time
%% ---------------------------------------------------------------------------

now_seconds() -> erlang:system_time(second).
now_millis() -> erlang:system_time(millisecond).

%% Seconds since the epoch of an RFC 3339 date-time with a time zone
%% (`2026-12-01T00:00:00Z`, `2026-12-01T01:00:00+01:00`). The shape and the
%% values are checked first: calendar:rfc3339_to_system_time/2 shifts what
%% does not exist (2026-02-30 is 2026-03-02, month 13 the next January) and
%% takes any separator between the date and the time.
parse_rfc3339(Bin) ->
    case valid_rfc3339(Bin) of
        false -> {error, nil};
        true ->
            try calendar:rfc3339_to_system_time(binary_to_list(Bin), [{unit, second}]) of
                Seconds -> {ok, Seconds}
            catch
                _:_ -> {error, nil}
            end
    end.

valid_rfc3339(<<Y:4/binary, "-", Mo:2/binary, "-", D:2/binary, T, H:2/binary, ":",
                Mi:2/binary, ":", S:2/binary, Rest/binary>>)
  when T =:= $T; T =:= $t ->
    case [digits(X) || X <- [Y, Mo, D, H, Mi, S]] of
        [Year, Month, Day, Hour, Minute, Second]
          when is_integer(Year), is_integer(Month), is_integer(Day),
               is_integer(Hour), is_integer(Minute), is_integer(Second) ->
            Month >= 1 andalso Month =< 12
                andalso calendar:valid_date(Year, Month, Day)
                andalso Hour =< 23 andalso Minute =< 59 andalso Second =< 60
                andalso valid_zone(skip_fraction(Rest));
        _ -> false
    end;
valid_rfc3339(_) -> false.

skip_fraction(<<".", Rest/binary>>) ->
    case skip_digits(Rest) of
        Rest -> invalid;
        After -> After
    end;
skip_fraction(Rest) -> Rest.

skip_digits(<<C, Rest/binary>>) when C >= $0, C =< $9 -> skip_digits(Rest);
skip_digits(Rest) -> Rest.

valid_zone(<<"Z">>) -> true;
valid_zone(<<"z">>) -> true;
valid_zone(<<Sign, H:2/binary, ":", M:2/binary>>) when Sign =:= $+; Sign =:= $- ->
    case {digits(H), digits(M)} of
        {Hours, Minutes} when is_integer(Hours), is_integer(Minutes) ->
            Hours =< 23 andalso Minutes =< 59;
        _ -> false
    end;
valid_zone(_) -> false.

%% The value of a binary of ASCII digits, or `error`.
digits(Bin) ->
    case Bin =/= <<>> andalso lists:all(fun(C) -> C >= $0 andalso C =< $9 end,
                                        binary_to_list(Bin)) of
        true -> binary_to_integer(Bin);
        false -> error
    end.

rfc3339(Seconds) ->
    list_to_binary(calendar:system_time_to_rfc3339(Seconds, [{offset, "Z"}])).

%% ---------------------------------------------------------------------------
%% Signals
%% ---------------------------------------------------------------------------

on_sighup(Callback) ->
    os:set_signal(sighup, handle),
    _ = gen_event:delete_handler(erl_signal_server, redirect_proxy_sighup, remove),
    ok = gen_event:add_handler(erl_signal_server, redirect_proxy_sighup, Callback),
    nil.

%% ---------------------------------------------------------------------------
%% CLI helpers
%% ---------------------------------------------------------------------------

plain_arguments() ->
    [unicode:characters_to_binary(A) || A <- init:get_plain_arguments()].

halt(Code) -> erlang:halt(Code).

read_password(Prompt) ->
    io:put_chars(Prompt),
    Echo = try io:setopts(standard_io, [{echo, false}]) catch _:_ -> error end,
    Line = io:get_line(""),
    case Echo of
        ok -> _ = io:setopts(standard_io, [{echo, true}]), io:nl();
        _ -> ok
    end,
    case Line of
        eof -> {error, nil};
        {error, _} -> {error, nil};
        Data -> {ok, string:trim(unicode:characters_to_binary(Data), trailing, "\r\n")}
    end.

%% ---------------------------------------------------------------------------
%% Runtime metrics
%% ---------------------------------------------------------------------------

app_version() ->
    case application:get_key(redirect_proxy, vsn) of
        {ok, Vsn} -> unicode:characters_to_binary(Vsn);
        undefined -> <<"unknown">>
    end.

%% When the VM started, in seconds since the epoch.
start_time_seconds() ->
    {UptimeMs, _} = erlang:statistics(wall_clock),
    erlang:system_time(second) - UptimeMs div 1000.

memory_bytes() -> erlang:memory(total).
process_count() -> erlang:system_info(process_count).

garbage_collect() ->
    erlang:garbage_collect(),
    nil.

%% Runs Fun, turning an exception into {error, Description}. gleam_httpc
%% raises on errors it does not know (a peer closing the connection...).
rescue(Fun) ->
    try {ok, Fun()}
    catch Class:Reason ->
        {error, unicode:characters_to_binary(
                  io_lib:format("~p: ~0p", [Class, Reason]))}
    end.

%% A store call that timed out: an error that `rescue_store_timeout` turns
%% into an answer (503), and that crashes the caller anywhere else.
store_timeout() ->
    erlang:error(redirect_proxy_store_timeout).

%% Runs Fun, or Unavailable when a store call in it timed out. Any other
%% exception goes through as it was.
rescue_store_timeout(Fun, Unavailable) ->
    try Fun()
    catch error:redirect_proxy_store_timeout -> Unavailable()
    end.
