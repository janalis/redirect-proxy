%% Test helpers: RSA key pair and ID token signing for the fake OIDC provider.
-module(test_jwt_ffi).
-export([keypair/0, sign/2]).

keypair() ->
    {ok, _} = application:ensure_all_started(jose),
    Jwk = jose_jwk:generate_key({rsa, 2048}),
    {_, Public} = jose_jwk:to_public_map(Jwk),
    Key = Public#{<<"kid">> => <<"test-key">>,
                  <<"alg">> => <<"RS256">>,
                  <<"use">> => <<"sig">>},
    {iolist_to_binary(json:encode(#{<<"keys">> => [Key]})), Jwk}.

sign(Jwk, ClaimsJson) ->
    Claims = json:decode(ClaimsJson),
    Header = #{<<"alg">> => <<"RS256">>, <<"kid">> => <<"test-key">>},
    {_, Token} = jose_jws:compact(jose_jwt:sign(Jwk, Header, Claims)),
    Token.
