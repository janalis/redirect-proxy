-module(test_signal_ffi).
-export([notify/1, handlers/0]).

%% Delivers a signal event the way erl_signal_server does, without the OS.
notify(Signal) ->
    ok = gen_event:sync_notify(erl_signal_server, binary_to_atom(Signal)),
    nil.

handlers() ->
    [atom_to_binary(H) || H <- gen_event:which_handlers(erl_signal_server)].
