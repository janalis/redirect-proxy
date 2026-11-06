-module(test_log_ffi).
-export([handler_level/0, primary_level/0, formatter_module/0, format_json/2]).

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
