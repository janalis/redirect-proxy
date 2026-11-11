%% Crypto: password hashing, constant-time comparison, JWT (OIDC id_token).
-module(redirect_proxy_crypto_ffi).

-export([
    jwt_peek_header/1, jwt_verify/2, pbkdf2_sha256/4, secure_compare/2
]).

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
                %% keys for signatures (not encryption), of this algorithm
                %% when they name one (RFC 7517 4.2, 4.4)
                Candidates = [K || K <- Keys,
                                   Kid =:= undefined orelse
                                   maps:get(<<"kid">>, K, Kid) =:= Kid,
                                   maps:get(<<"use">>, K, <<"sig">>) =:= <<"sig">>,
                                   maps:get(<<"alg">>, K, Alg) =:= Alg],
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
