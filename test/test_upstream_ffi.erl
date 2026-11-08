%% Test helper: a small HTTP/1.1 upstream (the website behind the redirect
%% listener), over TCP or TLS with a self-signed certificate.
%%
%% By default it echoes the request: "<method> <target>", the connection
%% number, the headers as received (one per line), how the body was framed
%% and the body. Some paths behave differently:
%%
%% - /chunked: a chunked response
%% - /close: a response delimited by the end of the connection
%% - /not-modified: a 304
%% - /hop: hop-by-hop headers in the response
%% - /date: a response with its own `date`
%% - /early-hints: a 103 before the echo
%% - /ws: 101 when asked for an upgrade, then every byte echoed back
%% - /slow: the echo after 1.5 s
%% - /once: the echo, then the connection closed (without saying so)
%% - /abrupt: the connection closed without a response
-module(test_upstream_ffi).
-export([start/0, start_tls/0, connections/1, closed_port/0]).

%% {Port, Counter}: Counter counts the accepted connections.
start() ->
    start(gen_tcp, []).

start_tls() ->
    {ok, _} = application:ensure_all_started(ssl),
    Key = [{key, {namedCurve, secp256r1}}, {digest, sha256}],
    Chain = #{root => Key, intermediates => [], peer => Key},
    #{server_config := Config} =
        public_key:pkix_test_data(#{server_chain => Chain, client_chain => Chain}),
    start(ssl, Config).

connections(Counter) -> counters:get(Counter, 1).

%% A port nothing listens on.
closed_port() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    ok = gen_tcp:close(L),
    Port.

start(Transport, Options) ->
    Counter = counters:new(1, []),
    Self = self(),
    spawn(fun() ->
        Listen = [binary, {active, false}, {reuseaddr, true}, {ip, {127, 0, 0, 1}} | Options],
        {ok, L} = Transport:listen(0, Listen),
        {ok, {_, Port}} = case Transport of
            gen_tcp -> inet:sockname(L);
            ssl -> ssl:sockname(L)
        end,
        Self ! {upstream_port, Port},
        accept(Transport, L, Counter)
    end),
    receive {upstream_port, Port} -> {Port, Counter} end.

accept(gen_tcp, L, Counter) ->
    {ok, S} = gen_tcp:accept(L),
    N = counters:get(Counter, 1) + 1,
    counters:add(Counter, 1, 1),
    Pid = spawn(fun() -> receive go -> serve({gen_tcp, S}, N, <<>>) end end),
    ok = gen_tcp:controlling_process(S, Pid),
    Pid ! go,
    accept(gen_tcp, L, Counter);
accept(ssl, L, Counter) ->
    {ok, T} = ssl:transport_accept(L),
    N = counters:get(Counter, 1) + 1,
    counters:add(Counter, 1, 1),
    Pid = spawn(fun() ->
        receive go ->
            case ssl:handshake(T, 5000) of
                {ok, S} -> serve({ssl, S}, N, <<>>);
                {error, _} -> ok
            end
        end
    end),
    ok = ssl:controlling_process(T, Pid),
    Pid ! go,
    accept(ssl, L, Counter).

send({M, S}, Data) -> M:send(S, Data).
recv({M, S}) -> M:recv(S, 0, 5000).
close({M, S}) -> M:close(S).

serve(Socket, N, Buffer) ->
    case head(Socket, Buffer) of
        {ok, Head, Rest} ->
            [RequestLine | Lines] = binary:split(Head, <<"\r\n">>, [global]),
            [Method, Target, _] = binary:split(RequestLine, <<" ">>, [global]),
            Headers = [list_to_tuple(binary:split(L, <<": ">>)) || L <- Lines],
            Path = hd(binary:split(Target, <<"?">>)),
            case Path of
                <<"/abrupt">> ->
                    close(Socket);
                _ ->
                    {Framing, Body, Rest1} = body(Socket, Headers, Rest),
                    respond(Socket, N, Method, Target, Path, Headers, Framing, Body, Rest1)
            end;
        closed ->
            ok
    end.

respond(Socket, N, Method, Target, Path, Headers, Framing, Body, Rest) ->
    Echo = iolist_to_binary([
        Method, " ", Target, "\nconn=", integer_to_binary(N), "\n",
        [[Name, ": ", Value, "\n"] || {Name, Value} <- Headers],
        "framing=", Framing, "\nbody=", Body]),
    case Path of
        <<"/chunked">> ->
            send(Socket, <<"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nx-trailer: 1\r\n\r\n">>),
            serve(Socket, N, Rest);
        <<"/close">> ->
            send(Socket, <<"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nuntil the end">>),
            close(Socket);
        <<"/not-modified">> ->
            send(Socket, <<"HTTP/1.1 304 Not Modified\r\netag: \"x\"\r\n\r\n">>),
            serve(Socket, N, Rest);
        <<"/hop">> ->
            send(Socket, <<"HTTP/1.1 200 OK\r\nConnection: X-Secret\r\nX-Secret: 1\r\nKeep-Alive: timeout=5\r\nX-Kept: yes\r\ncontent-length: 2\r\n\r\nok">>),
            serve(Socket, N, Rest);
        <<"/date">> ->
            send(Socket, <<"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\ncontent-length: 2\r\n\r\nok">>),
            serve(Socket, N, Rest);
        <<"/early-hints">> ->
            send(Socket, <<"HTTP/1.1 103 Early Hints\r\nlink: </a.css>\r\n\r\n">>),
            echo(Socket, N, Method, Echo, Rest);
        <<"/ws">> ->
            case lists:keymember(<<"upgrade">>, 1, Headers) of
                true ->
                    send(Socket, [<<"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n">>, Rest]),
                    tunnel(Socket);
                false ->
                    echo(Socket, N, Method, Echo, Rest)
            end;
        <<"/slow">> ->
            timer:sleep(1500),
            echo(Socket, N, Method, Echo, Rest);
        <<"/once">> ->
            %% kept alive as far as the response says, then closed
            send(Socket, [<<"HTTP/1.1 200 OK\r\ncontent-length: ">>,
                          integer_to_binary(byte_size(Echo)), <<"\r\n\r\n">>, Echo]),
            close(Socket);
        _ ->
            echo(Socket, N, Method, Echo, Rest)
    end.

echo(Socket, N, Method, Echo, Rest) ->
    send(Socket, [<<"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: ">>,
                  integer_to_binary(byte_size(Echo)), <<"\r\n\r\n">>,
                  case Method of <<"HEAD">> -> <<>>; _ -> Echo end]),
    serve(Socket, N, Rest).

tunnel(Socket) ->
    case recv(Socket) of
        {ok, Data} -> send(Socket, Data), tunnel(Socket);
        {error, _} -> close(Socket)
    end.

head(Socket, Buffer) ->
    case binary:split(Buffer, <<"\r\n\r\n">>) of
        [Head, Rest] -> {ok, Head, Rest};
        [_] ->
            case recv(Socket) of
                {ok, Data} -> head(Socket, <<Buffer/binary, Data/binary>>);
                {error, _} -> closed
            end
    end.

body(Socket, Headers, Buffer) ->
    case {lists:keyfind(<<"content-length">>, 1, Headers),
          lists:keyfind(<<"transfer-encoding">>, 1, Headers)} of
        {false, false} ->
            {<<"none">>, <<>>, Buffer};
        {{_, Length}, false} ->
            {Body, Rest} = exactly(Socket, binary_to_integer(Length), Buffer),
            {<<"length">>, Body, Rest};
        {false, {_, <<"chunked">>}} ->
            {Body, Rest} = chunks(Socket, Buffer, <<>>),
            {<<"chunked">>, Body, Rest}
    end.

exactly(_, N, Buffer) when byte_size(Buffer) >= N ->
    <<Body:N/binary, Rest/binary>> = Buffer,
    {Body, Rest};
exactly(Socket, N, Buffer) ->
    {ok, Data} = recv(Socket),
    exactly(Socket, N, <<Buffer/binary, Data/binary>>).

chunks(Socket, Buffer, Acc) ->
    case binary:split(Buffer, <<"\r\n">>) of
        [SizeLine, Rest] ->
            case binary_to_integer(SizeLine, 16) of
                0 ->
                    {<<"\r\n">>, Rest1} = exactly(Socket, 2, Rest),
                    {Acc, Rest1};
                Size ->
                    {Data, Rest1} = exactly(Socket, Size + 2, Rest),
                    chunks(Socket, Rest1, <<Acc/binary, (binary:part(Data, 0, Size))/binary>>)
            end;
        [_] ->
            {ok, Data} = recv(Socket),
            chunks(Socket, <<Buffer/binary, Data/binary>>, Acc)
    end.
