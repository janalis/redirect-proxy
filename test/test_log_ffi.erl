-module(test_log_ffi).
-export([handler_level/0, primary_level/0, formatter_module/0, format_json/2]).
-export([capture_start/0, capture_stop/0, capture_until/2, log/2]).

handler_level() ->
    {ok, #{level := Level}} = logger:get_handler_config(default),
    atom_to_binary(Level).

primary_level() ->
    #{level := Level} = logger:get_primary_config(),
    atom_to_binary(Level).

formatter_module() ->
    {ok, #{formatter := {Module, _}}} = logger:get_handler_config(default),
    atom_to_binary(Module).

%% A log event formatted by the JSON formatter. Kind: string, format or
%% report; Domain: [] or [redirect_proxy, access].
format_json(Kind, WithDomain) ->
    Msg = case Kind of
        <<"string">> -> {string, "plain \"text\""};
        <<"format">> -> {"~s=~B", ["n", 42]};
        <<"report">> -> {report, #{key => value}}
    end,
    Meta0 = #{time => 1793957405123456},
    Meta = case WithDomain of
        true -> Meta0#{domain => [redirect_proxy, access]};
        false -> Meta0
    end,
    iolist_to_binary(redirect_proxy_log_json:format(
        #{level => warning, msg => Msg, meta => Meta}, #{})).

%% Captures the messages logged by this process tree until capture_stop/0,
%% which returns them oldest first.
capture_start() ->
    Self = self(),
    _ = logger:remove_handler(test_capture),
    ok = logger:add_handler(test_capture, ?MODULE,
                            #{level => all, config => #{pid => Self}}),
    nil.

capture_stop() ->
    _ = logger:remove_handler(test_capture),
    collect([]).

%% Waits up to Timeout ms for a captured message containing Text, then stops
%% capturing: whether it came.
capture_until(Text, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    Found = wait_for(Text, Deadline),
    _ = logger:remove_handler(test_capture),
    _ = collect([]),
    Found.

wait_for(Text, Deadline) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {test_captured_log, Msg} ->
            case binary:match(Msg, Text) of
                nomatch -> wait_for(Text, Deadline);
                _ -> true
            end
    after Left -> false
    end.

collect(Acc) ->
    receive
        {test_captured_log, Msg} -> collect([Msg | Acc])
    after 0 -> lists:reverse(Acc)
    end.

%% logger handler callback
log(#{msg := Msg}, #{config := #{pid := Pid}}) ->
    Text = case Msg of
        {string, S} -> unicode:characters_to_binary(S);
        {report, R} -> iolist_to_binary(io_lib:format("~0p", [R]));
        {Format, Args} -> unicode:characters_to_binary(io_lib:format(Format, Args))
    end,
    Pid ! {test_captured_log, Text},
    ok.
