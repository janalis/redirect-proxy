%% Network: addresses, CIDRs, forwarded hops, throttling groups.
-module(redirect_proxy_net_ffi).

-export([
    cidrs_contain/2, cidrs_contain_ip/2, cidrs_contain_peer/2, cidrs_contain_peer_result/2,
    cidrs_empty/1, client_group/1, client_group_text/1, compile_cidrs/1,
    first_item/1, forwarded_hop/2, ip_in_cidr/2, is_ip_address/1,
    is_loopback_address/1, throttle_address/1, valid_cidr/1, valid_listen_address/1
]).

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

%% CIDRs parsed once: {V4, V6}, each a list of {Prefix, Shift} where Prefix
%% is the network as an integer shifted right by Shift (the host bits).
%% Invalid entries never match (configuration validation rejects them).
compile_cidrs(Bins) ->
    lists:foldr(
        fun(Bin, {V4, V6} = Acc) ->
            case parse_cidr(Bin) of
                {ok, {Net, Bits}} when tuple_size(Net) =:= 4 ->
                    {[{ip_to_int(Net) bsr (32 - Bits), 32 - Bits} | V4], V6};
                {ok, {Net, Bits}} ->
                    {V4, [{ip_to_int(Net) bsr (128 - Bits), 128 - Bits} | V6]};
                error -> Acc
            end
        end,
        {[], []}, Bins).

cidrs_empty({[], []}) -> true;
cidrs_empty(_) -> false.

%% Whether a mist IpAddress ({ip_v4, ...} or {ip_v6, ...}) is in the CIDRs.
cidrs_contain_peer({[], []}, _) -> false;
cidrs_contain_peer(Cidrs, {ip_v4, A, B, C, D}) -> cidrs_contain_ip({A, B, C, D}, Cidrs);
cidrs_contain_peer(Cidrs, {ip_v6, A, B, C, D, E, F, G, H}) ->
    cidrs_contain_ip({A, B, C, D, E, F, G, H}, Cidrs).

%% cidrs_contain_peer/2 of a peer when known ({ok, IpAddress}).
cidrs_contain_peer_result({[], []}, _) -> false;
cidrs_contain_peer_result(Cidrs, {ok, Peer}) -> cidrs_contain_peer(Cidrs, Peer);
cidrs_contain_peer_result(_, _) -> false.

%% The client address in X-Forwarded-For lines (in order; several lines are
%% one comma-separated list): the rightmost hop that is not in Trusted, or
%% the leftmost when all are. {ok, Ip} when that hop is an IP address, else
%% {error, nil}. Byte splits and trims, each hop parsed once: this runs on
%% every request from a trusted proxy.
forwarded_hop(Lines, Trusted) ->
    Hops = [H || Line <- Lines, Item <- binary:split(Line, <<",">>, [global]),
                 H <- [trim_ows(Item)], H =/= <<>>],
    rightmost_untrusted(lists:reverse(Hops), Trusted).

rightmost_untrusted([], _) ->
    {error, nil};
rightmost_untrusted([Hop], Trusted) ->
    %% untrusted, or the leftmost of trusted ones: the answer either way
    _ = Trusted,
    as_ip(Hop);
rightmost_untrusted([Hop | Rest], Trusted) ->
    case parse_ip(Hop) of
        {ok, Ip} ->
            case cidrs_contain_ip(Ip, Trusted) of
                true -> rightmost_untrusted(Rest, Trusted);
                false -> {ok, Hop}
            end;
        _ ->
            %% not an address: not a trusted proxy, so the client, which
            %% is not usable
            {error, nil}
    end.

as_ip(Hop) ->
    case parse_ip(Hop) of
        {ok, _} -> {ok, Hop};
        _ -> {error, nil}
    end.

%% The first item of a comma-separated header value, without surrounding
%% whitespace, ASCII lower-cased (`X-Forwarded-Proto: HTTPS, http`).
first_item(Value) ->
    Item = case binary:match(Value, <<",">>) of
        {At, 1} -> binary:part(Value, 0, At);
        nomatch -> Value
    end,
    redirect_proxy_text_ffi:lowercase_ascii(trim_ows(Item)).

trim_ows(Bin) -> trim_ows_end(trim_ows_start(Bin)).

trim_ows_start(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t -> trim_ows_start(Rest);
trim_ows_start(Bin) -> Bin.

trim_ows_end(<<>>) -> <<>>;
trim_ows_end(Bin) ->
    case binary:last(Bin) of
        C when C =:= $\s; C =:= $\t -> trim_ows_end(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ -> Bin
    end.

%% Whether an address (text) is in the CIDRs; false when it is not one.
cidrs_contain({[], []}, _) -> false;
cidrs_contain(Cidrs, IpBin) ->
    case parse_ip(IpBin) of
        {ok, Ip} -> cidrs_contain_ip(Ip, Cidrs);
        _ -> false
    end.

%% As ip_in_cidr/2: IPv4 addresses match IPv4 networks, IPv6 addresses
%% IPv6 networks, and IPv4-mapped IPv6 addresses both IPv6 networks and the
%% IPv4 networks of their IPv4 address.
cidrs_contain_ip({_, _, _, _} = Ip, {V4, _}) ->
    V4 =/= [] andalso int_in_cidrs(ip_to_int(Ip), V4);
cidrs_contain_ip({0, 0, 0, 0, 0, 16#ffff, A, B} = Ip, {V4, V6}) ->
    (V4 =/= [] andalso int_in_cidrs((A bsl 16) bor B, V4))
        orelse (V6 =/= [] andalso int_in_cidrs(ip_to_int(Ip), V6));
cidrs_contain_ip(Ip, {_, V6}) when tuple_size(Ip) =:= 8 ->
    V6 =/= [] andalso int_in_cidrs(ip_to_int(Ip), V6);
cidrs_contain_ip(_, _) -> false.

int_in_cidrs(_, []) -> false;
int_in_cidrs(Int, [{Prefix, Shift} | Rest]) ->
    (Int bsr Shift) =:= Prefix orelse int_in_cidrs(Int, Rest).

%% The address that throttling counts failures for: IPv4 addresses as they
%% are, IPv6 addresses by /64 (one host usually holds a whole /64, so
%% counting single addresses would give it unlimited attempts). IPv4-mapped
%% IPv6 addresses count as IPv4. Anything else is returned unchanged.
throttle_address(IpBin) ->
    case parse_ip(IpBin) of
        {ok, Ip} -> client_group_text(client_group(Ip));
        _ -> IpBin
    end.

%% The group an address counts in, for throttling and connection limits:
%% {v4, Ip} for IPv4 (and IPv4-mapped IPv6) addresses, {v6, Prefix} (the
%% /64, the rest zeroed) for IPv6 ones.
client_group({0, 0, 0, 0, 0, 16#ffff, A, B}) ->
    {v4, {A bsr 8, A band 255, B bsr 8, B band 255}};
client_group({A, B, C, D, _, _, _, _}) -> {v6, {A, B, C, D, 0, 0, 0, 0}};
client_group(Ip) -> {v4, Ip}.

client_group_text({v4, Ip}) -> list_to_binary(inet:ntoa(Ip));
client_group_text({v6, Prefix}) -> <<(list_to_binary(inet:ntoa(Prefix)))/binary, "/64">>.

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
ip_to_int({A, B, C, D, E, F, G, H}) ->
    (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64)
        bor (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H.
