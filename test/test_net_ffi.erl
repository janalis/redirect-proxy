%% Test helper: an unused TCP port on the loopback interface.
-module(test_net_ffi).
-export([free_port/0]).

free_port() ->
    {ok, Socket} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Socket),
    ok = gen_tcp:close(Socket),
    Port.
