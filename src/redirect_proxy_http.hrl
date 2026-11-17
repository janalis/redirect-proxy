%% What the redirect listener's connection process (`redirect_proxy_http`)
%% shares with its reverse proxy (`redirect_proxy_upstream`).

-record(conn, {
    socket,
    handler,
    peer,
    idle_timeout,
    max_head,
    %% none | the monotonic time (ms) by which the request head being read
    %% must be complete: bytes trickled in do not extend it
    deadline = none,
    %% {Second, Rendered} of the last `date` header
    date = {0, <<>>},
    %% none | #up{}: where unanswered requests are forwarded
    upstream = none,
    %% none | {gen_tcp | ssl, Socket}: the open upstream connection
    up = none
}).

%% packets delivered as messages before the socket must be re-armed
-define(ACTIVE, 64).

%% The kinds of warning `redirect_proxy_http:limited/2` logs at most once
%% a second: about the upstream, the listener and a client address;
%% ?WARNED_KINDS slots.
-define(UPSTREAM_LOG, 1).
-define(LISTENER_LOG, 2).
-define(ADDRESS_LOG, 3).
-define(WARNED_KINDS, 3).
