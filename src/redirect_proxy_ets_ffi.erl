%% ETS tables (sessions, rate limiting, failure windows, slots) and atomic
%% counters (metrics).
-module(redirect_proxy_ets_ffi).

-export([
    counter_add/3, counter_get/2, counter_new/1, counter_put/3,
    counter_size/1, ets_delete/2, ets_delete_older/2, ets_find/2,
    ets_get/2, ets_insert_new/3, ets_new/1, ets_put/3,
    ets_replace_if/4, ets_delete_if/3,
    ets_size/1, ets_to_list/1, password_check_slots/0, window_forgive/3, window_take_receipt/5, window_record_receipt/4,
    window_get/2, window_purge/2, window_record/4, window_take/5,
    with_slot/4
]).

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

%% `ets_get`, for a table that may not exist yet: a miss then.
ets_find(Table, Key) ->
    try ets:lookup(binary_to_existing_atom(Table), Key) of
        [{_, Value}] -> {ok, Value};
        [] -> {error, nil}
    catch
        error:badarg -> {error, nil}
    end.

ets_delete(Table, Key) ->
    ets:delete(binary_to_existing_atom(Table), Key),
    nil.

%% Compare against the exact value read by a caller. Constants prevent
%% stored values from being interpreted as match-spec syntax.
ets_replace_if(Table, Key, Old, New) when is_binary(Key) ->
    ets:select_replace(binary_to_existing_atom(Table),
        [{{Key, '$1'}, [{'=:=', '$1', {const, Old}}],
          [{{Key, {const, New}}}]}]) =:= 1;
ets_replace_if(Table, Key, Old, New) ->
    ets:select_replace(binary_to_existing_atom(Table),
        [{{'$1', '$2'}, [{'=:=', '$1', {const, Key}},
                         {'=:=', '$2', {const, Old}}],
          [{{'$1', {const, New}}}]}]) =:= 1.

ets_delete_if(Table, Key, Old) when is_binary(Key) ->
    ets:select_delete(binary_to_existing_atom(Table),
        [{{Key, '$1'}, [{'=:=', '$1', {const, Old}}], [true]}]) =:= 1;
ets_delete_if(Table, Key, Old) ->
    ets:select_delete(binary_to_existing_atom(Table),
        [{{'$1', '$2'}, [{'=:=', '$1', {const, Key}},
                         {'=:=', '$2', {const, Old}}], [true]}]) =:= 1.

ets_to_list(Table) ->
    ets:tab2list(binary_to_existing_atom(Table)).

ets_size(Table) ->
    ets:info(binary_to_existing_atom(Table), size).

%% Delete every entry whose value is a tuple with an expiry (first element)
%% older than Now. Used to purge sessions and rate-limit windows.
%% Adds Key unless it is already there: true when it was added (atomic).
ets_insert_new(Table, Key, Value) ->
    ets:insert_new(binary_to_existing_atom(Table), {Key, Value}).

ets_delete_older(Table, Now) ->
    T = binary_to_existing_atom(Table),
    ets:select_delete(T, [{{'_', '$1'},
                           [{'andalso', {is_tuple, '$1'},
                             {'<', {element, 1, '$1'}, Now}}],
                           [true]}]).

%% ---------------------------------------------------------------------------
%% Failure windows: {Key, WindowEnd, Count, Generation}. Admission and
%% refunds compare the exact generation, even across resets and restarts.
%% ---------------------------------------------------------------------------

window_record(Table, Key, Now, Window) ->
    {ok, _} = window_record_receipt(Table, Key, Now, Window),
    nil.

window_record_receipt(Table, Key, Now, Window) ->
    window_take_receipt(Table, Key, Now, Window, infinity).

window_take(Table, Key, Now, Window, Limit) ->
    case window_take_receipt(Table, Key, Now, Window, Limit) of
        {ok, _} -> {ok, nil};
        Error -> Error
    end.

window_take_receipt(Table, Key, Now, Window, Limit) ->
    window_take_retry(binary_to_existing_atom(Table), Key, Now, Window, Limit).

window_take_retry(T, Key, Now, Window, Limit) ->
    case ets:lookup(T, Key) of
        [{Key, End, _, _} = Old] when End =< Now ->
            true = ets:delete_object(T, Old),
            window_take_retry(T, Key, Now, Window, Limit);
        [{Key, End, Count, _}] when Count >= Limit ->
            {error, max(1, End - Now)};
        [{Key, End, Count, Generation}] ->
            Replaced = ets:select_replace(T,
                [{{Key, '$1', '$2', '$3'},
                  [{'=:=', '$1', End}, {'=:=', '$2', Count},
                   {'=:=', '$3', Generation}],
                  [{const, {Key, End, Count + 1, Generation}}]}]),
            case Replaced of
                1 -> {ok, Generation};
                0 -> window_take_retry(T, Key, Now, Window, Limit)
            end;
        [] when Limit > 0 ->
            %% Browser-held SSO receipts can outlive a VM restart: do not
            %% reuse a generation when the process-local sequence restarts.
            Generation = binary:decode_unsigned(crypto:strong_rand_bytes(16)),
            case ets:insert_new(T, {Key, Now + Window, 1, Generation}) of
                true -> {ok, Generation};
                false -> window_take_retry(T, Key, Now, Window, Limit)
            end;
        [] ->
            {error, max(1, Window)}
    end.

%% Refund only the window that admitted the work, even when a reset and
%% replacement happen in the same second with the same expiry.
window_forgive(Table, Key, Generation) ->
    T = binary_to_existing_atom(Table),
    case ets:lookup(T, Key) of
        [{Key, End, Count, Generation}] when Count > 0 ->
            Changed = ets:select_replace(T,
                [{{Key, '$1', '$2', '$3'},
                  [{'=:=', '$1', End}, {'=:=', '$2', Count},
                   {'=:=', '$3', Generation}],
                  [{const, {Key, End, Count - 1, Generation}}]}]),
            case Changed of
                1 -> nil;
                0 -> window_forgive(Table, Key, Generation)
            end;
        _ -> nil
    end.

%% Runs Fun when fewer than Max live processes hold a Key slot: {ok, Result},
%% or {error, nil} at once when they are all taken. Each holder is an entry
%% of its own ({Key, Pid, Ref}), added before the holders are counted, so
%% that racing callers never exceed Max (at worst both are refused). The
%% entry is removed when Fun returns or raises; the entry of a process
%% killed in Fun (no `after` then) is removed by the next caller, so a slot
%% is never lost for good.
with_slot(Table, Key, Max, Fun) ->
    T = binary_to_existing_atom(Table),
    Self = {Key, self(), make_ref()},
    true = ets:insert(T, {Self}),
    Holders = [H || {{_, Pid, _} = H} <- ets:match_object(T, {{Key, '_', '_'}}),
                    holds_slot(T, H, Pid)],
    case length(Holders) > Max of
        true ->
            ets:delete(T, Self),
            {error, nil};
        false ->
            try {ok, Fun()}
            after ets:delete(T, Self)
            end
    end.

holds_slot(T, Holder, Pid) ->
    case is_process_alive(Pid) of
        true -> true;
        false ->
            ets:delete(T, Holder),
            false
    end.

%% Password hashes allowed at once: half the dirty CPU schedulers (where
%% crypto runs PBKDF2), at least 2, so that a burst of logins leaves CPU for
%% the redirect listener.
password_check_slots() ->
    max(2, erlang:system_info(dirty_cpu_schedulers_online) div 2).

window_get(Table, Key) ->
    case ets:lookup(binary_to_existing_atom(Table), Key) of
        [{_, WindowEnd, Count, _}] -> {ok, {WindowEnd, Count}};
        [] -> {error, nil}
    end.

window_purge(Table, Now) ->
    ets:select_delete(binary_to_existing_atom(Table),
                      [{{'_', '$1', '_', '_'}, [{'=<', '$1', Now}], [true]}]).

%% ---------------------------------------------------------------------------
%% Atomic counters (metrics)
%% ---------------------------------------------------------------------------

counter_new(Size) -> counters:new(Size, [write_concurrency]).
counter_size(Ref) -> maps:get(size, counters:info(Ref)).
counter_add(Ref, Index, Amount) -> counters:add(Ref, Index, Amount), nil.
counter_get(Ref, Index) -> counters:get(Ref, Index).
counter_put(Ref, Index, Value) -> counters:put(Ref, Index, Value), nil.
