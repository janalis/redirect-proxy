-module(redirect_proxy_ffi).

-export([
    snapshot_put/2, snapshot_get/1,
    regex_compile/2, regex_run/2, regex_limit_init/0, regex_limit_count/0,
    count_regex_limit/0, reductions/0,
    atomic_write/2, atomic_write_private/2, append_line/2, memo_file/2, file_stamp/1, stamp_is_recent/1,
    pbkdf2_sha256/4, secure_compare/2,
    ets_new/1, ets_put/3, ets_get/2, ets_delete/2, ets_to_list/1, ets_size/1,
    ets_delete_older/2, ets_insert_new/3,
         window_record/4, window_get/2, window_purge/2, window_take/5, window_forgive/2,
    with_slot/4, password_check_slots/0,
    counter_new/1, counter_add/3, counter_get/2, counter_put/3,
    ip_in_cidr/2, is_ip_address/1, throttle_address/1, valid_cidr/1, valid_listen_address/1, is_loopback_address/1,
    now_seconds/0, now_millis/0, rfc3339/1, parse_rfc3339/1,
    on_sighup/1,
    plain_arguments/0, halt/1, read_password/1,
    memory_bytes/0, process_count/0, app_version/0, start_time_seconds/0,
    jwt_verify/2, jwt_peek_header/1,
    with_lock/2, with_file_lock/3, tunable/2, set_tunable/2, clear_tunable/1, strip_control/1, header_value/1, strip_url_whitespace/1, garbage_collect/0,
    no_control_chars/1,
    is_host_name/1, lowercase_host/1, lowercase_ascii/1, url_host/1,
    split_lines/1,
    binary_take/2, binary_drop/2, binary_contains/2, binary_replace_all/3, rescue/1, store_timeout/0, rescue_store_timeout/2,
    normalise_path/1, is_ascii/1, needs_trim/1,
    encode_cached/2, strip_port/1, data_dir_owner_mismatch/1
]).

-include_lib("kernel/include/file.hrl").

-define(MATCH_LIMIT, 100000).
-define(IS_HEX(C), ((C >= $0 andalso C =< $9) orelse (C >= $a andalso C =< $f) orelse (C >= $A andalso C =< $F))).

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

%% The keys read on every request are atoms: `persistent_term` hashes its
%% key on each read, and hashing `{redirect_proxy, <<"matcher">>}` costs
%% more than the read itself.
snapshot_key(<<"matcher">>) -> redirect_proxy_matcher;
snapshot_key(<<"metrics">>) -> redirect_proxy_metrics;
snapshot_key(<<"metrics_latency">>) -> redirect_proxy_metrics_latency;
snapshot_key(Key) -> {redirect_proxy, Key}.

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

%% Reductions spent by the calling process so far: what the regex stage of a
%% request may spend is measured with it (re:run counts its work in
%% reductions).
reductions() ->
    {reductions, R} = erlang:process_info(self(), reductions),
    R.

count_regex_limit() ->
    case persistent_term:get({redirect_proxy, regex_limit}, undefined) of
        undefined -> ok;
        Ref -> counters:add(Ref, 1, 1)
    end.

%% ---------------------------------------------------------------------------
%% Files
%% ---------------------------------------------------------------------------

atomic_write(Path, Content) -> atomic_write(Path, Content, default).

%% For files holding secrets (password hashes, client secret hashes, the
%% cookie signing key): created 0600 instead of the umask default.
atomic_write_private(Path, Content) -> atomic_write(Path, Content, 8#600).

atomic_write(Path, Content, NewMode) ->
    _ = filelib:ensure_dir(Path),
    Tmp = <<Path/binary, ".tmp.", (integer_to_binary(erlang:unique_integer([positive])))/binary>>,
    %% Every step returns {error, _} instead of raising, so that a full or
    %% failing disk is reported to the caller and the temp file is removed.
    Result =
        case file:open(Tmp, [write, raw, binary]) of
            {ok, Fd} ->
                %% before the content is written: a secret is never readable
                %% by others, not even for a moment
                set_mode(Path, Tmp, NewMode),
                Written = write_and_sync(Fd, Content),
                Closed = file:close(Fd),
                case {Written, Closed} of
                    {ok, ok} ->
                        case file:rename(Tmp, Path) of
                            ok -> sync_dir(filename:dirname(Path));
                            RenameError -> RenameError
                        end;
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

%% The new file replaces the old one: give it the old one's permissions
%% (e.g. 0640 for a group-readable redirections file) instead of the umask
%% default. A new file gets NewMode, or the umask default.
set_mode(Path, Tmp, NewMode) ->
    case {file:read_file_info(Path), NewMode} of
        {{ok, #file_info{mode = Mode}}, _} -> _ = file:change_mode(Tmp, Mode band 8#7777);
        {{error, _}, default} -> ok;
        {{error, _}, _} -> _ = file:change_mode(Tmp, NewMode)
    end,
    ok.

%% Makes the rename durable: without it, a power loss right after a write
%% can bring the old file back. Best effort: a file system that cannot open
%% or sync a directory leaves the rename as it is.
sync_dir(Dir) ->
    case file:open(Dir, [read, raw, directory]) of
        {ok, Fd} ->
            _ = file:sync(Fd),
            _ = file:close(Fd),
            ok;
        {error, _} -> ok
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

%% Fun() computed from a file, cached until the file changes. Writes replace
%% the file (atomic_write renames a new one), so the inode tells versions
%% apart even within the second of mtime. When Fun() fails, the last good
%% value is kept (a corrupt or half-written file does not break readers).
%% Changes when a file is replaced (inode), written (mtime) or resized.
file_stamp(Path) ->
    case file:read_file_info(Path, [{time, posix}]) of
        {ok, #file_info{inode = Inode, mtime = MTime, size = Size}} ->
            {Inode, MTime, Size};
        {error, _} -> missing
    end.

%% Whether a stamp's modification time is within the last two seconds:
%% another write in that same second would leave the stamp as it is (the
%% time has a one second resolution) when it keeps the size and the inode.
stamp_is_recent({_, MTime, _}) -> MTime >= os:system_time(second) - 2;
stamp_is_recent(missing) -> false.

memo_file(Path, Fun) ->
    Stamp = file_stamp(Path),
    Table = memo_table(),
    Cached = try ets:lookup(Table, Path) catch error:badarg -> [] end,
    case Cached of
        [{_, Stamp, Value}] -> Value;
        _ ->
            case Fun() of
                {ok, _} = Ok ->
                    try ets:insert(Table, {Path, Stamp, Ok})
                    catch error:badarg -> ok
                    end,
                    Ok;
                Error ->
                    case Cached of
                        [{_, _, {ok, _} = Last}] -> Last;
                        _ -> Error
                    end
            end
    end.

memo_table() ->
    case ets:whereis(redirect_proxy_memo) of
        undefined ->
            Self = self(),
            Owner = spawn(fun() ->
                try ets:new(redirect_proxy_memo, [named_table, public, set,
                                                  {read_concurrency, true}])
                catch error:badarg -> ok  % created concurrently
                end,
                Self ! {redirect_proxy_memo, self()},
                receive after infinity -> ok end
            end),
            receive {redirect_proxy_memo, Owner} -> ok after 1000 -> ok end;
        _ -> ok
    end,
    redirect_proxy_memo.

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
%% Failure windows (login throttling): rows are {Key, WindowEnd, Count} so
%% that concurrent failures are counted atomically (ets:update_counter).
%% ---------------------------------------------------------------------------

window_record(Table, Key, Now, Window) ->
    T = binary_to_existing_atom(Table),
    %% an ended window starts over (each call is atomic on its own; two
    %% failures racing here both count in the new window)
    _ = ets:select_delete(T, [{{Key, '$1', '_'}, [{'=<', '$1', Now}], [true]}]),
    _ = ets:update_counter(T, Key, {3, 1}, {Key, Now + Window, 0}),
    nil.

%% Counts one use of Key, atomically, when it stays within Limit in the
%% current window: {ok, nil}, or {error, SecondsLeft} with nothing counted.
%% Checking and counting in one step: concurrent attempts cannot all pass a
%% check made before any of them is counted.
window_take(Table, Key, Now, Window, Limit) ->
    T = binary_to_existing_atom(Table),
    _ = ets:select_delete(T, [{{Key, '$1', '_'}, [{'=<', '$1', Now}], [true]}]),
    case ets:update_counter(T, Key, {3, 1}, {Key, Now + Window, 0}) of
        Count when Count > Limit ->
            _ = ets:update_counter(T, Key, {3, -1, 0, 0}),
            %% the entry may have been purged since (an ended window)
            WindowEnd = case ets:lookup(T, Key) of
                [{_, End, _}] -> End;
                [] -> Now + Window
            end,
            {error, max(1, WindowEnd - Now)};
        _ -> {ok, nil}
    end.

%% Takes back one counted use of Key (never below zero).
window_forgive(Table, Key) ->
    try ets:update_counter(binary_to_existing_atom(Table), Key, {3, -1, 0, 0}) of
        _ -> nil
    catch
        error:badarg -> nil
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
        [{_, WindowEnd, Count}] -> {ok, {WindowEnd, Count}};
        [] -> {error, nil}
    end.

window_purge(Table, Now) ->
    ets:select_delete(binary_to_existing_atom(Table),
                      [{{'_', '$1', '_'}, [{'=<', '$1', Now}], [true]}]).

%% ---------------------------------------------------------------------------
%% Atomic counters (metrics)
%% ---------------------------------------------------------------------------

counter_new(Size) -> counters:new(Size, [write_concurrency]).
counter_add(Ref, Index, Amount) -> counters:add(Ref, Index, Amount), nil.
counter_get(Ref, Index) -> counters:get(Ref, Index).
counter_put(Ref, Index, Value) -> counters:put(Ref, Index, Value), nil.

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

%% The address that throttling counts failures for: IPv4 addresses as they
%% are, IPv6 addresses by /64 (one host usually holds a whole /64, so
%% counting single addresses would give it unlimited attempts). IPv4-mapped
%% IPv6 addresses count as IPv4. Anything else is returned unchanged.
throttle_address(IpBin) ->
    case parse_ip(IpBin) of
        {ok, {0, 0, 0, 0, 0, 16#ffff, A, B}} ->
            list_to_binary(inet:ntoa({A bsr 8, A band 255, B bsr 8, B band 255}));
        {ok, {A, B, C, D, _, _, _, _}} ->
            <<(list_to_binary(inet:ntoa({A, B, C, D, 0, 0, 0, 0})))/binary, "/64">>;
        {ok, Ip} when tuple_size(Ip) =:= 4 -> list_to_binary(inet:ntoa(Ip));
        _ -> IpBin
    end.

is_ip_address(Bin) ->
    case parse_ip(Bin) of
        {ok, _} -> true;
        _ -> false
    end.

valid_cidr(CidrBin) ->
    case parse_cidr(CidrBin) of
        {ok, _} -> true;
        _ -> false
    end.

%% What the HTTP server accepts to listen on (glisten:bind/2 panics on
%% anything else): an IP address or "localhost".
valid_listen_address(<<"localhost">>) -> true;
valid_listen_address(Bin) ->
    case inet:parse_address(binary_to_list(Bin)) of
        {ok, _} -> true;
        _ -> false
    end.

is_loopback_address(<<"localhost">>) -> true;
is_loopback_address(Bin) ->
    Trimmed = string:trim(Bin, both, "[]"),
    case inet:parse_address(binary_to_list(Trimmed)) of
        {ok, {127, _, _, _}} -> true;
        {ok, {0, 0, 0, 0, 0, 0, 0, 1}} -> true;
        %% IPv4-mapped (::ffff:127.0.0.1)
        {ok, {0, 0, 0, 0, 0, 16#ffff, A, _}} -> A bsr 8 =:= 127;
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

%% Seconds since the epoch of an RFC 3339 date-time with a time zone
%% (`2026-12-01T00:00:00Z`, `2026-12-01T01:00:00+01:00`). The shape and the
%% values are checked first: calendar:rfc3339_to_system_time/2 shifts what
%% does not exist (2026-02-30 is 2026-03-02, month 13 the next January) and
%% takes any separator between the date and the time.
parse_rfc3339(Bin) ->
    case valid_rfc3339(Bin) of
        false -> {error, nil};
        true ->
            try calendar:rfc3339_to_system_time(binary_to_list(Bin), [{unit, second}]) of
                Seconds -> {ok, Seconds}
            catch
                _:_ -> {error, nil}
            end
    end.

valid_rfc3339(<<Y:4/binary, "-", Mo:2/binary, "-", D:2/binary, T, H:2/binary, ":",
                Mi:2/binary, ":", S:2/binary, Rest/binary>>)
  when T =:= $T; T =:= $t ->
    case [digits(X) || X <- [Y, Mo, D, H, Mi, S]] of
        [Year, Month, Day, Hour, Minute, Second]
          when is_integer(Year), is_integer(Month), is_integer(Day),
               is_integer(Hour), is_integer(Minute), is_integer(Second) ->
            Month >= 1 andalso Month =< 12
                andalso calendar:valid_date(Year, Month, Day)
                andalso Hour =< 23 andalso Minute =< 59 andalso Second =< 60
                andalso valid_zone(skip_fraction(Rest));
        _ -> false
    end;
valid_rfc3339(_) -> false.

skip_fraction(<<".", Rest/binary>>) ->
    case skip_digits(Rest) of
        Rest -> invalid;
        After -> After
    end;
skip_fraction(Rest) -> Rest.

skip_digits(<<C, Rest/binary>>) when C >= $0, C =< $9 -> skip_digits(Rest);
skip_digits(Rest) -> Rest.

valid_zone(<<"Z">>) -> true;
valid_zone(<<"z">>) -> true;
valid_zone(<<Sign, H:2/binary, ":", M:2/binary>>) when Sign =:= $+; Sign =:= $- ->
    case {digits(H), digits(M)} of
        {Hours, Minutes} when is_integer(Hours), is_integer(Minutes) ->
            Hours =< 23 andalso Minutes =< 59;
        _ -> false
    end;
valid_zone(_) -> false.

%% The value of a binary of ASCII digits, or `error`.
digits(Bin) ->
    case Bin =/= <<>> andalso lists:all(fun(C) -> C >= $0 andalso C =< $9 end,
                                        binary_to_list(Bin)) of
        true -> binary_to_integer(Bin);
        false -> error
    end.

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

app_version() ->
    case application:get_key(redirect_proxy, vsn) of
        {ok, Vsn} -> unicode:characters_to_binary(Vsn);
        undefined -> <<"unknown">>
    end.

%% When the VM started, in seconds since the epoch.
start_time_seconds() ->
    {UptimeMs, _} = erlang:statistics(wall_clock),
    erlang:system_time(second) - UptimeMs div 1000.

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

%% A lock not refreshed for this long is left over by a crashed process: its
%% holder refreshes it while it runs (`start_lock_refresher`).
-define(STALE_LOCK_SECONDS, 10).

%% A delay that tests shorten (`set_tunable`): read where a lock is judged
%% stale or a store call starts, never on the request path.
tunable(Name, Default) ->
    persistent_term:get({?MODULE, tunable, Name}, Default).

set_tunable(Name, Value) ->
    persistent_term:put({?MODULE, tunable, Name}, Value),
    nil.

clear_tunable(Name) ->
    _ = persistent_term:erase({?MODULE, tunable, Name}),
    nil.

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
            Refresher = start_lock_refresher(Lock, Token),
            try {ok, Fun()}
            after
                stop_lock_refresher(Refresher),
                release_lock(Lock, Token)
            end;
        %% A directory this process cannot create files in is one it cannot
        %% write the rules to either (writes are a temp file and a rename):
        %% a replica reading a read-only volume. Run without the lock; the
        %% writers of other processes replace the file atomically.
        read_only ->
            {ok, Fun()};
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
        {error, Read} when Read =:= eacces; Read =:= erofs; Read =:= eperm ->
            read_only;
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

%% While the lock is held (a matcher build, fsyncs and the audit may take
%% longer than the stale delay on a large rule set), a linked process sets
%% its modification time to now, five times per stale delay, so that no
%% waiter takes it over. It dies with the holder.
start_lock_refresher(Lock, Token) ->
    Interval = max(100, stale_lock_seconds() * 200),
    spawn_link(fun() -> refresh_lock(Lock, Token, Interval) end).

stop_lock_refresher(Refresher) ->
    unlink(Refresher),
    exit(Refresher, kill),
    ok.

refresh_lock(Lock, Token, Interval) ->
    receive after Interval -> ok end,
    %% only this acquisition's lock: never one taken over meanwhile
    _ = case file:read_file(Lock) of
        {ok, Token} ->
            Now = os:system_time(second),
            file:write_file_info(Lock, #file_info{atime = Now, mtime = Now},
                                 [{time, posix}]);
        _ -> ok
    end,
    refresh_lock(Lock, Token, Interval).

%% Releases the lock only while it still holds this acquisition's token.
release_lock(Lock, Token) ->
    case file:read_file(Lock) of
        {ok, Token} -> _ = file:delete(Lock), ok;
        _ -> ok
    end.

%% File times come from the OS clock: compared with it, not with the VM's
%% system time, which lags or leads it after the OS clock is stepped (no
%% time warp), and would then take a fresh lock for a stale one.
is_stale_file(Path) ->
    case file:read_file_info(Path, [{time, posix}]) of
        {ok, {file_info, _, _, _, _, MTime, _, _, _, _, _, _, _, _}} ->
            MTime < os:system_time(second) - stale_lock_seconds();
        _ -> false
    end.

stale_lock_seconds() ->
    tunable(<<"stale_lock_seconds">>, ?STALE_LOCK_SECONDS).

lock_owner(Lock) ->
    case file:read_file(Lock) of
        {ok, Content} -> string:trim(Content);
        _ -> <<"unknown">>
    end.

%% Removes CR, LF and NUL bytes (header injection guard), byte-wise so that
%% "\r\n" grapheme clusters are handled too.
%% Tabs and line breaks, which browsers drop from URLs. A byte scan: most
%% locations have none, and are returned as they are.
strip_url_whitespace(Bin) ->
    case has_url_whitespace(Bin) of
        false -> Bin;
        true -> << <<C>> || <<C>> <= Bin, C =/= $\t, C =/= $\n, C =/= $\r >>
    end.

has_url_whitespace(<<C, _/binary>>) when C =:= $\t; C =:= $\n; C =:= $\r -> true;
has_url_whitespace(<<_, Rest/binary>>) -> has_url_whitespace(Rest);
has_url_whitespace(<<>>) -> false.

strip_control(Bin) ->
    binary:replace(Bin, [<<"\r">>, <<"\n">>, <<0>>], <<>>, [global]).

%% On every redirect (Location): a byte scan, and the value returned as is
%% when it has no CR, LF, NUL or non-ASCII byte, instead of binary:replace,
%% which compiles its pattern on every call.
header_value(Bin) ->
    case needs_cleaning(Bin) of
        false -> Bin;
        true -> encode_non_ascii(strip_control(Bin))
    end.

needs_cleaning(<<C, _/binary>>) when C >= 16#80; C =:= $\r; C =:= $\n; C =:= 0 -> true;
needs_cleaning(<<_, Rest/binary>>) -> needs_cleaning(Rest);
needs_cleaning(<<>>) -> false.

garbage_collect() ->
    erlang:garbage_collect(),
    nil.

%% No byte below 32, nor DEL. The bytes of a multi-byte UTF-8 character are
%% all 128 or more: the same as checking its code points, without listing
%% them.
no_control_chars(<<C, _/binary>>) when C < 32; C =:= 127 -> false;
no_control_chars(<<_, Rest/binary>>) -> no_control_chars(Rest);
no_control_chars(<<>>) -> true.

%% Runs Fun, turning an exception into {error, Description}. gleam_httpc
%% raises on errors it does not know (a peer closing the connection...).
rescue(Fun) ->
    try {ok, Fun()}
    catch Class:Reason ->
        {error, unicode:characters_to_binary(
                  io_lib:format("~p: ~0p", [Class, Reason]))}
    end.

%% A store call that timed out: an error that `rescue_store_timeout` turns
%% into an answer (503), and that crashes the caller anywhere else.
store_timeout() ->
    erlang:error(redirect_proxy_store_timeout).

%% Runs Fun, or Unavailable when a store call in it timed out. Any other
%% exception goes through as it was.
rescue_store_timeout(Fun, Unavailable) ->
    try Fun()
    catch error:redirect_proxy_store_timeout -> Unavailable()
    end.

%% ---------------------------------------------------------------------------
%% Path normalisation
%% ---------------------------------------------------------------------------

%% One form for equivalent paths, applied to request paths and rule sources:
%% %XX escapes of unreserved characters (A-Z a-z 0-9 - . _ ~) and of valid
%% UTF-8 sequences are decoded (/caf%C3%A9 -> /café), and the escapes kept
%% (reserved characters such as %2F, %3F, %23, %25, invalid UTF-8) are
%% written in upper case. A lone `%` is written %25. Then the `.` and `..`
%% segments are removed (RFC 3986, 5.2.4), after the decoding so that
%% `%2E%2E` counts: a capture must not climb out of its target's path
%% (`/docs/../../b` with `/docs/(.*)` -> `https://cdn/a/$1`). Applying it
%% twice gives the same result.
normalise_path(Path) ->
    Decoded = case has_percent(Path) of
        false -> Path;
        true -> iolist_to_binary(normalise(Path))
    end,
    remove_dot_segments(Decoded).

%% Only absolute paths; `/.` is searched first (a BIF scan) so that the usual
%% path is returned as is.
remove_dot_segments(<<"/", _/binary>> = Path) ->
    case binary:match(Path, <<"/.">>) of
        nomatch -> Path;
        _ ->
            [<<>> | Segments] = binary:split(Path, <<"/">>, [global]),
            case lists:any(fun is_dot_segment/1, Segments) of
                false -> Path;
                true ->
                    Kept = drop_dots(Segments, []),
                    iolist_to_binary([[<<"/">>, S] || S <- Kept])
            end
    end;
remove_dot_segments(Path) -> Path.

is_dot_segment(<<".">>) -> true;
is_dot_segment(<<"..">>) -> true;
is_dot_segment(_) -> false.

%% A dot segment that ends the path leaves a trailing `/` (`/a/b/..` ->
%% `/a/`); `..` above the root stays at the root.
drop_dots([], Acc) -> lists:reverse(Acc);
drop_dots([<<".">>], Acc) -> lists:reverse([<<>> | Acc]);
drop_dots([<<"..">>], Acc) -> lists:reverse([<<>> | pop(Acc)]);
drop_dots([<<".">> | Rest], Acc) -> drop_dots(Rest, Acc);
drop_dots([<<"..">> | Rest], Acc) -> drop_dots(Rest, pop(Acc));
drop_dots([S | Rest], Acc) -> drop_dots(Rest, [S | Acc]).

pop([]) -> [];
pop([_ | Acc]) -> Acc.

%% On every request: a plain scan, cheaper than binary:match for short paths.
has_percent(<<$%, _/binary>>) -> true;
has_percent(<<_, Rest/binary>>) -> has_percent(Rest);
has_percent(<<>>) -> false.

normalise(<<"%", H1, H2, Rest/binary>>) when ?IS_HEX(H1), ?IS_HEX(H2) ->
    Byte = hex_value(H1) * 16 + hex_value(H2),
    if
        Byte < 16#80 ->
            case is_unreserved(Byte) of
                true -> [Byte | normalise(Rest)];
                false -> [escape(Byte) | normalise(Rest)]
            end;
        true ->
            {Bytes, After} = escaped_bytes(Rest, [Byte]),
            Sequence = list_to_binary(Bytes),
            case unicode:characters_to_binary(Sequence) of
                Sequence -> [Sequence | normalise(After)];
                _ -> [[escape(B) || B <- Bytes] | normalise(After)]
            end
    end;
%% A `%` that does not start an escape is written %25: left as is, it could
%% form a new escape with characters decoded next to it (%f%37 -> %f7).
normalise(<<"%", Rest/binary>>) -> [<<"%25">> | normalise(Rest)];
normalise(<<C, Rest/binary>>) -> [C | normalise(Rest)];
normalise(<<>>) -> [].

%% The following %XX escapes of bytes >= 0x80 (a UTF-8 sequence).
escaped_bytes(<<"%", H1, H2, Rest/binary>> = Bin, Acc)
  when ?IS_HEX(H1), ?IS_HEX(H2) ->
    case hex_value(H1) * 16 + hex_value(H2) of
        Byte when Byte >= 16#80 -> escaped_bytes(Rest, [Byte | Acc]);
        _ -> {lists:reverse(Acc), Bin}
    end;
escaped_bytes(Bin, Acc) -> {lists:reverse(Acc), Bin}.

is_unreserved(C) when C >= $a, C =< $z; C >= $A, C =< $Z; C >= $0, C =< $9 -> true;
is_unreserved(C) -> lists:member(C, "-._~").

hex_value(C) when C >= $0, C =< $9 -> C - $0;
hex_value(C) when C >= $a, C =< $f -> C - $a + 10;
hex_value(C) when C >= $A, C =< $F -> C - $A + 10.

escape(Byte) -> <<"%", (hex(Byte bsr 4)), (hex(Byte band 15))>>.

hex(N) when N < 10 -> $0 + N;
hex(N) -> $A + N - 10.

%% Percent-encodes the bytes >= 0x80 of a URL, for headers (Location) that
%% must be ASCII.
encode_non_ascii(Url) ->
    case has_non_ascii(Url) of
        false -> Url;
        true -> << <<(case C >= 16#80 of true -> escape(C); false -> <<C>> end)/binary>>
                   || <<C>> <= Url >>
    end.

is_ascii(Bin) -> not has_non_ascii(Bin).

%% Whether string:trim could change Bin: its first or last byte is a space,
%% a control character or not ASCII (Unicode white space is decided by
%% string:trim itself). Gleam's string.trim compiles its patterns on every
%% call: a rule set is trimmed field by field when it loads.
needs_trim(<<>>) -> false;
needs_trim(Bin) ->
    not (is_plain(binary:first(Bin)) andalso is_plain(binary:last(Bin))).

is_plain(C) -> C > 32 andalso C < 127.

has_non_ascii(<<C, _/binary>>) when C >= 16#80 -> true;
has_non_ascii(<<_, Rest/binary>>) -> has_non_ascii(Rest);
has_non_ascii(<<>>) -> false.

%% Request hosts, on every request: byte scans instead of grapheme walks.
%% Only lower-case letters, digits, `-`, `_` and `.` make a host name.
is_host_name(<<>>) -> false;
is_host_name(Host) -> host_bytes(Host).

host_bytes(<<C, Rest/binary>>)
  when (C >= $a andalso C =< $z); (C >= $0 andalso C =< $9);
       C =:= $-; C =:= $_; C =:= $. -> host_bytes(Rest);
host_bytes(<<>>) -> true;
host_bytes(_) -> false.

%% ASCII is lowered byte by byte; anything else goes through Unicode case
%% mapping, as string:lowercase/1 does.
lowercase_host(Host) ->
    case has_non_ascii(Host) of
        false -> lowercase_ascii(Host);
        true -> string:lowercase(Host)
    end.

%% Lowers the ASCII letters only, byte by byte: other bytes are kept, so any
%% binary (even one cut inside a UTF-8 sequence) stays as valid as it was.
lowercase_ascii(Bin) ->
    case has_upper(Bin) of
        %% the usual host or path: returned as is, not rebuilt
        false -> Bin;
        true ->
            << <<(case C >= $A andalso C =< $Z of true -> C + 32; false -> C end)>>
               || <<C>> <= Bin >>
    end.

has_upper(<<C, _/binary>>) when C >= $A, C =< $Z -> true;
has_upper(<<_, Rest/binary>>) -> has_upper(Rest);
has_upper(<<>>) -> false.

%% The host of what follows `scheme://` in a URL: up to the first `/`, `\`,
%% `?` or `#`, after the last `@` (user info). Byte searches: the delimiters
%% are ASCII, and URLs are parsed by code point, not grapheme cluster. One
%% scan (on every prefix or regex redirect whose target has a host):
%% binary:match with a list of patterns compiles them on every call.
url_host(Rest) -> url_host(Rest, 0, 0).

%% Pos: the byte looked at; Start: after the last `@` so far.
url_host(Url, Pos, Start) ->
    case Url of
        <<_:Pos/binary, C, _/binary>> when C =:= $/; C =:= $\\; C =:= $?; C =:= $# ->
            binary:part(Url, Start, Pos - Start);
        <<_:Pos/binary, $@, _/binary>> ->
            url_host(Url, Pos + 1, Pos + 1);
        <<_:Pos/binary, _, _/binary>> ->
            url_host(Url, Pos + 1, Start);
        _ ->
            binary:part(Url, Start, Pos - Start)
    end.

%% The lines of a binary, as binaries (not decoded).
split_lines(Bin) -> binary:split(Bin, <<"\n">>, [global]).

%% Byte-wise slicing for the matcher's prefix index. The first N bytes may
%% end inside a UTF-8 sequence: they are only used as a dictionary key.
binary_take(Bin, N) when byte_size(Bin) >= N -> binary:part(Bin, 0, N);
binary_take(Bin, _N) -> Bin.

%% Byte-wise search and replace: `string` functions compare graphemes, and a
%% quote or comma followed by a combining mark is one grapheme with it.
binary_contains(Bin, Pattern) -> binary:match(Bin, Pattern) =/= nomatch.

binary_replace_all(Bin, Pattern, Replacement) ->
    binary:replace(Bin, Pattern, Replacement, [global]).

binary_drop(Bin, N) when byte_size(Bin) >= N ->
    binary:part(Bin, N, byte_size(Bin) - N);
binary_drop(_Bin, _N) -> <<>>.

%% Encodes each of Items with Encode, reusing what the calling process
%% encoded last time for an equal item (the whole term is the key, so a
%% changed item is encoded again). Only the current items are kept: the
%% cache never grows past one list. Returns the encodings, in order.
encode_cached(Items, Encode) ->
    Old = case erlang:get(redirect_proxy_encode_cache) of
        undefined -> #{};
        Map -> Map
    end,
    {Encoded, New} = lists:mapfoldl(
        fun(Item, Acc) ->
            Value = case Old of
                #{Item := Cached} -> Cached;
                _ -> Encode(Item)
            end,
            {Value, Acc#{Item => Value}}
        end, #{}, Items),
    erlang:put(redirect_proxy_encode_cache, New),
    Encoded.

%% A host without its port: `[::1]:8080` -> `[::1]`, `a.test:80` -> `a.test`.
%% Byte splits: on every request, and for every rule of a rebuild.
strip_port(<<"[", _/binary>> = Host) ->
    case binary:split(Host, <<"]">>) of
        [Addr, _] -> <<Addr/binary, "]">>;
        [_] -> Host
    end;
strip_port(Host) ->
    case binary:split(Host, <<":">>) of
        [Name, _] -> Name;
        [_] -> Host
    end.

%% When the calling OS process runs as root and Dir belongs to another
%% user: {ok, OwnerName}. Otherwise (or when it cannot be told) error.
data_dir_owner_mismatch(Dir) ->
    Uid = string:trim(os:cmd("id -u")),
    case {Uid, file:read_file_info(Dir)} of
        {"0", {ok, #file_info{uid = Owner}}} when Owner =/= 0 ->
            Name = string:trim(os:cmd("id -nu " ++ integer_to_list(Owner) ++ " 2>/dev/null")),
            {ok, unicode:characters_to_binary(case Name of
                "" -> integer_to_list(Owner);
                _ -> Name
            end)};
        _ -> {error, nil}
    end.
