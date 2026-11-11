%% persistent_term snapshot (lock-free reads from every request process).
-module(redirect_proxy_snapshot_ffi).

-export([
    snapshot_get/1, snapshot_or_init/2, snapshot_put/2
]).

%% ---------------------------------------------------------------------------
%% persistent_term snapshot (lock-free reads from every request process)
%% ---------------------------------------------------------------------------

snapshot_put(Key, Value) ->
    persistent_term:put(snapshot_key(Key), Value),
    nil.

snapshot_get(Key) ->
    case persistent_term:get(snapshot_key(Key), '$redirect_proxy_none') of
        '$redirect_proxy_none' -> {error, nil};
        Value -> {ok, Value}
    end.

%% The value of Key, published from Init() the first time. Racing first
%% callers take a lock, so that one value is published and the others read
%% it (a second put would replace counters already incremented).
snapshot_or_init(Key, Init) ->
    K = snapshot_key(Key),
    case persistent_term:get(K, '$redirect_proxy_none') of
        '$redirect_proxy_none' ->
            global:trans({{?MODULE, K}, self()}, fun() ->
                case persistent_term:get(K, '$redirect_proxy_none') of
                    '$redirect_proxy_none' ->
                        Value = Init(),
                        persistent_term:put(K, Value),
                        Value;
                    Value ->
                        Value
                end
            end, [node()]);
        Value ->
            Value
    end.

%% The keys read on every request are atoms: `persistent_term` hashes its
%% key on each read, and hashing `{redirect_proxy, <<"matcher">>}` costs
%% more than the read itself.
snapshot_key(<<"matcher">>) -> redirect_proxy_matcher;
snapshot_key(<<"metrics">>) -> redirect_proxy_metrics;
snapshot_key(<<"metrics_latency">>) -> redirect_proxy_metrics_latency;
snapshot_key(Key) -> {redirect_proxy, Key}.
