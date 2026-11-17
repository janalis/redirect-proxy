%% Unpublishes the rule set, for snapshot_test (the key of
%% redirect_proxy_snapshot_ffi:snapshot_key(<<"matcher">>)).
-module(test_snapshot_ffi).

-export([unpublish/0]).

unpublish() ->
    _ = persistent_term:erase(redirect_proxy_matcher),
    nil.
