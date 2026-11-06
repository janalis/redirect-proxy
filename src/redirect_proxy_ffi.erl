-module(redirect_proxy_ffi).

-export([
    snapshot_put/2, snapshot_get/1,
    regex_compile/2, regex_run/2, regex_limit_init/0, regex_limit_count/0,
    atomic_write/2, append_line/2,
    pbkdf2_sha256/4, secure_compare/2,
    ets_new/1, ets_put/3, ets_get/2, ets_delete/2, ets_to_list/1,
    ets_delete_older/2,
    counter_new/1, counter_add/3, counter_get/2,
    ip_in_cidr/2, valid_cidr/1,
    now_seconds/0, now_millis/0, rfc3339/1,
    on_sighup/1,
    plain_arguments/0, halt/1, read_password/1,
    memory_bytes/0, process_count/0,
    jwt_verify/2, jwt_peek_header/1,
    with_lock/2, with_file_lock/3, strip_control/1, garbage_collect/0,
    binary_take/2, binary_drop/2
]).

-define(MATCH_LIMIT, 100000).

%% ---------------------------------------------------------------------------
%% persistent_term snapshot (lock-free reads from every request process)
%% ---------------------------------------------------------------------------

snapshot_put(Key, Value) ->
    persistent_term:put({redirect_proxy, Key}, Value),
    nil.

snapshot_get(Key) ->
    case persistent_term:get({redirect_proxy, Key}, '$redirect_proxy_none') of
        '$redirect_proxy_none' -> {error, nil};
        Value -> {ok, Value}
    end.

%% ---------------------------------------------------------------------------
%% Regular expressions with a backtracking budget (ReDoS guard)
%% ---------------------------------------------------------------------------

regex_compile(Pattern, CaseInsensitive) ->
    Options = case CaseInsensitive of
        true -> [unicode, caseless];
        false -> [unicode]
    end,
    case re:compile(Pattern, Options) of
        {ok, MP} -> {ok, MP};
        {error, {Reason, Position}} ->
            {error, unicode:characters_to_binary(
                io_lib:format("~s at position ~B", [Reason, Position]))}
    end.

%% Returns {ok, Captures} where Captures includes group 0, {error, nil} on no
%% match and {error, limit} if the match limit was exhausted.
regex_run(MP, Subject) ->
    case re:run(Subject, MP, [{capture, all, binary},
                              {match_limit, ?MATCH_LIMIT},
                              {match_limit_recursion, ?MATCH_LIMIT},
                              report_errors]) of
        {match, Captures} -> {ok, Captures};
        nomatch -> {error, no_match};
        {error, _} -> count_regex_limit(), {error, limit_exceeded}
    end.

%% Number of regex runs that exhausted their budget (a metric). The counter
%% is created at boot by regex_limit_init/0.
regex_limit_init() ->
    case persistent_term:get({redirect_proxy, regex_limit}, undefined) of
        undefined ->
            persistent_term:put({redirect_proxy, regex_limit},
                                counters:new(1, [write_concurrency]));
        _ -> ok
    end,
    nil.

regex_limit_count() ->
    case persistent_term:get({redirect_proxy, regex_limit}, undefined) of
        undefined -> 0;
        Ref -> counters:get(Ref, 1)
    end.

count_regex_limit() ->
    case persistent_term:get({redirect_proxy, regex_limit}, undefined) of
        undefined -> ok;
        Ref -> counters:add(Ref, 1, 1)
    end.

%% ---------------------------------------------------------------------------
%% Files
%% ---------------------------------------------------------------------------

atomic_write(Path, Content) ->
    _ = filelib:ensure_dir(Path),
    Tmp = <<Path/binary, ".tmp.", (integer_to_binary(erlang:unique_integer([positive])))/binary>>,
    %% Every step returns {error, _} instead of raising, so that a full or
    %% failing disk is reported to the caller and the temp file is removed.
    Result =
        case file:open(Tmp, [write, raw, binary]) of
            {ok, Fd} ->
                Written = write_and_sync(Fd, Content),
                Closed = file:close(Fd),
                case {Written, Closed} of
                    {ok, ok} -> file:rename(Tmp, Path);
                    {ok, CloseError} -> CloseError;
                    {WriteError, _} -> WriteError
                end;
            Error -> Error
        end,
    case Result of
        ok -> {ok, nil};
        {error, Reason} ->
            _ = file:delete(Tmp),
            {error, atom_to_binary_safe(Reason)}
    end.

write_and_sync(Fd, Content) ->
    case file:write(Fd, Content) of
        ok -> file:sync(Fd);
        Error -> Error
    end.

append_line(Path, Line) ->
    case file:write_file(Path, [Line, $\n], [append, raw]) of
        ok -> {ok, nil};
        {error, Reason} -> {error, atom_to_binary_safe(Reason)}
    end.

atom_to_binary_safe(A) when is_atom(A) -> atom_to_binary(A);
atom_to_binary_safe(T) -> unicode:characters_to_binary(io_lib:format("~p", [T])).

%% ---------------------------------------------------------------------------
%% Crypto
%% ---------------------------------------------------------------------------

pbkdf2_sha256(Password, Salt, Iterations, Length) ->
    crypto:pbkdf2_hmac(sha256, Password, Salt, Iterations, Length).

secure_compare(A, B) when byte_size(A) =:= byte_size(B) ->
    crypto:hash_equals(A, B);
secure_compare(_, _) ->
    false.

%% ---------------------------------------------------------------------------
%% ETS (sessions, rate limiting, hit counters)
%% ---------------------------------------------------------------------------

ets_new(Name) ->
    Atom = binary_to_atom(Name),
    case ets:whereis(Atom) of
        undefined ->
            ets:new(Atom, [set, public, named_table,
                           {read_concurrency, true},
                           {write_concurrency, auto},
                           {decentralized_counters, true}]);
        _ -> ok
    end,
    nil.

ets_put(Table, Key, Value) ->
    ets:insert(binary_to_existing_atom(Table), {Key, Value}),
    nil.

ets_get(Table, Key) ->
    case ets:lookup(binary_to_existing_atom(Table), Key) of
        [{_, Value}] -> {ok, Value};
        [] -> {error, nil}
    end.

ets_delete(Table, Key) ->
    ets:delete(binary_to_existing_atom(Table), Key),
    nil.

ets_to_list(Table) ->
    ets:tab2list(binary_to_existing_atom(Table)).

%% Delete every entry whose value is a tuple with an expiry (first element)
%% older than Now. Used to purge sessions and rate-limit windows.
ets_delete_older(Table, Now) ->
    T = binary_to_existing_atom(Table),
    ets:select_delete(T, [{{'_', '$1'},
                           [{'andalso', {is_tuple, '$1'},
                             {'<', {element, 1, '$1'}, Now}}],
                           [true]}]).

%% ---------------------------------------------------------------------------
%% Atomic counters (metrics)
%% ---------------------------------------------------------------------------

counter_new(Size) -> counters:new(Size, [write_concurrency]).
counter_add(Ref, Index, Amount) -> counters:add(Ref, Index, Amount), nil.
counter_get(Ref, Index) -> counters:get(Ref, Index).

%% ---------------------------------------------------------------------------
%% Network
%% ---------------------------------------------------------------------------

ip_in_cidr(IpBin, CidrBin) ->
    case {parse_ip(IpBin), parse_cidr(CidrBin)} of
        {{ok, Ip}, {ok, {Net, Bits}}} when tuple_size(Ip) =:= tuple_size(Net) ->
            Width = tuple_size(Ip) * (case tuple_size(Ip) of 4 -> 8; 8 -> 16 end),
            Shift = Width - Bits,
            (ip_to_int(Ip) bsr Shift) =:= (ip_to_int(Net) bsr Shift);
        {{ok, {0, 0, 0, 0, 0, 16#ffff, A, B}}, {ok, {Net, _}}} when tuple_size(Net) =:= 4 ->
            V4 = {A bsr 8, A band 255, B bsr 8, B band 255},
            ip_in_cidr(list_to_binary(inet:ntoa(V4)), CidrBin);
        _ -> false
    end.

valid_cidr(CidrBin) ->
    case parse_cidr(CidrBin) of
        {ok, _} -> true;
        _ -> false
    end.

parse_ip(Bin) ->
    inet:parse_strict_address(binary_to_list(Bin)).

parse_cidr(Bin) ->
    case binary:split(Bin, <<"/">>) of
        [Addr, BitsBin] ->
            Bits0 = try binary_to_integer(BitsBin) catch _:_ -> invalid end,
            case {parse_ip(Addr), Bits0} of
                {{ok, Ip}, Bits} when is_integer(Bits), Bits >= 0,
                        ((tuple_size(Ip) =:= 4 andalso Bits =< 32) orelse
                         (tuple_size(Ip) =:= 8 andalso Bits =< 128)) ->
                    {ok, {Ip, Bits}};
                _ -> error
            end;
        [Addr] ->
            case parse_ip(Addr) of
                {ok, Ip} when tuple_size(Ip) =:= 4 -> {ok, {Ip, 32}};
                {ok, Ip} -> {ok, {Ip, 128}};
                _ -> error
            end
    end.

ip_to_int({A, B, C, D}) -> (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
ip_to_int(T) when tuple_size(T) =:= 8 ->
    lists:foldl(fun(X, Acc) -> (Acc bsl 16) bor X end, 0, tuple_to_list(T)).

%% ---------------------------------------------------------------------------
%% Time
%% ---------------------------------------------------------------------------

now_seconds() -> erlang:system_time(second).
now_millis() -> erlang:system_time(millisecond).

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

memory_bytes() -> erlang:memory(total).
process_count() -> erlang:system_info(process_count).

%% ---------------------------------------------------------------------------
%% JWT (OIDC id_token) verification using erlang-jose
%% ---------------------------------------------------------------------------

%% JwksJson: the JSON document served at jwks_uri.
%% Returns {ok, ClaimsJson} when the signature is valid with one of the keys.
jwt_verify(JwksJson, Token) ->
    try
        #{<<"keys">> := Keys} = json:decode(JwksJson),
        Header = json:decode(jose_jws:peek_protected(Token)),
        Alg = maps:get(<<"alg">>, Header),
        Allowed = [<<"RS256">>, <<"RS384">>, <<"RS512">>, <<"ES256">>,
                   <<"ES384">>, <<"ES512">>, <<"PS256">>, <<"PS384">>,
                   <<"PS512">>, <<"EdDSA">>],
        case lists:member(Alg, Allowed) of
            false -> {error, <<"unsupported signing algorithm: ", Alg/binary>>};
            true ->
                Kid = maps:get(<<"kid">>, Header, undefined),
                Candidates = [K || K <- Keys,
                                   Kid =:= undefined orelse
                                   maps:get(<<"kid">>, K, Kid) =:= Kid],
                verify_with(Candidates, Alg, Token)
        end
    catch
        _:Reason -> {error, unicode:characters_to_binary(io_lib:format("invalid token: ~p", [Reason]))}
    end.

verify_with([], _Alg, _Token) ->
    {error, <<"no matching key could verify the token signature">>};
verify_with([KeyMap | Rest], Alg, Token) ->
    Jwk = jose_jwk:from_map(KeyMap),
    Verified = try jose_jwt:verify_strict(Jwk, [Alg], Token)
               catch _:_ -> false end,
    case Verified of
        {true, Jwt, _Jws} ->
            {_, Claims} = jose_jwt:to_map(Jwt),
            {ok, iolist_to_binary(json:encode(Claims))};
        _ -> verify_with(Rest, Alg, Token)
    end.

jwt_peek_header(Token) ->
    try {ok, jose_jws:peek_protected(Token)}
    catch _:_ -> {error, nil}
    end.

%% ---------------------------------------------------------------------------
%% Node-local mutual exclusion
%% ---------------------------------------------------------------------------

with_lock(Name, Fun) ->
    global:trans({{redirect_proxy, Name}, self()}, Fun, [node()], infinity).

%% ---------------------------------------------------------------------------
%% Cross-process file lock (<Path>.lock, created with O_EXCL)
%% ---------------------------------------------------------------------------

%% A lock older than this is left over by a crashed process: writes hold the
%% lock for milliseconds.
-define(STALE_LOCK_SECONDS, 10).

%% Runs Fun while holding <Path>.lock, shared by every OS process (server,
%% CLI) that writes Path. Returns {ok, Result} or {error, Reason} when the
%% lock is not acquired within TimeoutMs.
%%
%% The lock file holds a token unique to this acquisition, so that a holder
%% only ever removes its own lock: when it was held past the stale delay and
%% another process broke it, releasing leaves the new owner's lock in place.
with_file_lock(Path, TimeoutMs, Fun) ->
    Lock = <<Path/binary, ".lock">>,
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    %% the data directory may not exist yet (first CLI command)
    _ = filelib:ensure_dir(Lock),
    Token = lock_token(),
    case acquire_lock(Lock, Token, Deadline) of
        ok ->
            try {ok, Fun()}
            after release_lock(Lock, Token)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

lock_token() ->
    iolist_to_binary(io_lib:format("~s ~s ~B~n",
        [os:getpid(), node(), erlang:unique_integer([positive])])).

acquire_lock(Lock, Token, Deadline) ->
    case file:open(Lock, [write, exclusive, raw, binary]) of
        {ok, Fd} ->
            Written = file:write(Fd, Token),
            _ = file:close(Fd),
            case Written of
                ok -> ok;
                {error, Reason} ->
                    %% an empty lock would never be released by its token
                    _ = file:delete(Lock),
                    {error, <<"cannot write ", Lock/binary, ": ",
                              (atom_to_binary_safe(Reason))/binary>>}
            end;
        {error, eexist} ->
            case break_stale_lock(Lock) of
                true -> acquire_lock(Lock, Token, Deadline);
                false ->
                    case erlang:monotonic_time(millisecond) >= Deadline of
                        true ->
                            {error, <<Lock/binary, " is held by another process (",
                                      (lock_owner(Lock))/binary, ")">>};
                        false ->
                            timer:sleep(5 + rand:uniform(20)),
                            acquire_lock(Lock, Token, Deadline)
                    end
            end;
        {error, Reason} ->
            {error, <<"cannot create ", Lock/binary, ": ",
                      (atom_to_binary_safe(Reason))/binary>>}
    end.

%% Removes a stale lock and returns true when the caller should retry at
%% once. Several waiters may see the same stale lock: breaking it holds
%% <Lock>.break (created with O_EXCL) and checks again that the lock is
%% stale, so a waiter never deletes the fresh lock another one just took.
break_stale_lock(Lock) ->
    case is_stale_file(Lock) of
        false -> false;
        true ->
            Breaker = <<Lock/binary, ".break">>,
            case file:open(Breaker, [write, exclusive, raw]) of
                {ok, Fd} ->
                    _ = file:close(Fd),
                    _ = case is_stale_file(Lock) of
                        true -> file:delete(Lock);
                        false -> ok
                    end,
                    _ = file:delete(Breaker),
                    true;
                {error, _} ->
                    %% another waiter is breaking it (held for microseconds):
                    %% a breaker left by a crash is removed in turn
                    _ = case is_stale_file(Breaker) of
                        true -> file:delete(Breaker);
                        false -> ok
                    end,
                    false
            end
    end.

%% Releases the lock only while it still holds this acquisition's token.
release_lock(Lock, Token) ->
    case file:read_file(Lock) of
        {ok, Token} -> _ = file:delete(Lock), ok;
        _ -> ok
    end.

is_stale_file(Path) ->
    case file:read_file_info(Path, [{time, posix}]) of
        {ok, {file_info, _, _, _, _, MTime, _, _, _, _, _, _, _, _}} ->
            MTime < erlang:system_time(second) - ?STALE_LOCK_SECONDS;
        _ -> false
    end.

lock_owner(Lock) ->
    case file:read_file(Lock) of
        {ok, Content} -> string:trim(Content);
        _ -> <<"unknown">>
    end.

%% Removes CR, LF and NUL bytes (header injection guard), byte-wise so that
%% "\r\n" grapheme clusters are handled too.
strip_control(Bin) ->
    binary:replace(Bin, [<<"\r">>, <<"\n">>, <<0>>], <<>>, [global]).

garbage_collect() ->
    erlang:garbage_collect(),
    nil.

%% Byte-wise slicing for the matcher's prefix index. The first N bytes may
%% end inside a UTF-8 sequence: they are only used as a dictionary key.
binary_take(Bin, N) when byte_size(Bin) >= N -> binary:part(Bin, 0, N);
binary_take(Bin, _N) -> Bin.

binary_drop(Bin, N) when byte_size(Bin) >= N ->
    binary:part(Bin, N, byte_size(Bin) - N);
binary_drop(_Bin, _N) -> <<>>.
