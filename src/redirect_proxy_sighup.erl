%% gen_event handler installed into erl_signal_server so that SIGHUP triggers
%% a reload of the redirections file. Every other signal is forwarded to the
%% default OTP handler behaviour (ignored here, handled by erl_signal_handler).
-module(redirect_proxy_sighup).
-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2, code_change/3]).

init(Callback) -> {ok, Callback}.

handle_event(sighup, Callback) ->
    try Callback() catch _:_ -> ok end,
    {ok, Callback};
handle_event(_Signal, Callback) ->
    {ok, Callback}.

handle_call(_Request, Callback) -> {ok, ok, Callback}.
handle_info(_Info, Callback) -> {ok, Callback}.
terminate(_Arg, _Callback) -> ok.
code_change(_OldVsn, Callback, _Extra) -> {ok, Callback}.
