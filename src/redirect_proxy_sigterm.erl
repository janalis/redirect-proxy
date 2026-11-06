%% Graceful shutdown. Replaces OTP's default signal handler, which stops the
%% VM as soon as SIGTERM arrives, by one that first drains: /readyz answers
%% 503 and the redirect listener closes kept-alive connections, so that load
%% balancers stop sending traffic, then the VM stops after a grace period.
%% A second SIGTERM stops it at once. Every other signal is handled as OTP
%% does (erl_signal_handler).
-module(redirect_proxy_sigterm).
-behaviour(gen_event).

-export([install/1, draining/0, set_draining/1]).
-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2, code_change/3]).

-define(FLAG, {redirect_proxy, draining}).

install(GraceMs) ->
    _ = gen_event:delete_handler(erl_signal_server, ?MODULE, remove),
    _ = gen_event:delete_handler(erl_signal_server, erl_signal_handler, remove),
    ok = gen_event:add_handler(erl_signal_server, ?MODULE, GraceMs),
    nil.

draining() ->
    persistent_term:get(?FLAG, false).

%% For tests: a real SIGTERM would stop the test node.
set_draining(Value) ->
    persistent_term:put(?FLAG, Value),
    nil.

init(GraceMs) ->
    {ok, Default} = erl_signal_handler:init([]),
    {ok, #{grace => GraceMs, default => Default}}.

handle_event(sigterm, #{grace := GraceMs} = S) ->
    case draining() of
        true ->
            ok = init:stop();
        false ->
            logger:notice(iolist_to_binary(io_lib:format(
                "SIGTERM received: draining for ~B ms, then stopping",
                [GraceMs]))),
            persistent_term:put(?FLAG, true),
            _ = spawn(fun() -> timer:sleep(GraceMs), init:stop() end)
    end,
    {ok, S};
handle_event(Signal, #{default := Default} = S) ->
    {ok, Default1} = erl_signal_handler:handle_event(Signal, Default),
    {ok, S#{default := Default1}}.

handle_call(_Request, S) -> {ok, ok, S}.
handle_info(_Info, S) -> {ok, S}.
terminate(_Arg, _S) -> ok.
code_change(_OldVsn, S, _Extra) -> {ok, S}.
