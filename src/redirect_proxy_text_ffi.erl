%% Bytes and text on the request path: header and URL guards, path
%% normalisation, hosts, byte slicing.
-module(redirect_proxy_text_ffi).

-export([
    binary_contains/2, binary_drop/2, binary_replace_all/3, binary_take/2,
    encode_cached/2, header_value/1, is_ascii/1, is_host_name/1,
    lowercase_ascii/1, lowercase_host/1, needs_trim/1, no_control_chars/1,
    normalise_path/1, split_lines/1, strip_control/1, strip_port/1,
    strip_url_whitespace/1, url_host/1
]).

-define(IS_HEX(C), ((C >= $0 andalso C =< $9) orelse (C >= $a andalso C =< $f) orelse (C >= $A andalso C =< $F))).

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

%% No byte below 32, nor DEL. The bytes of a multi-byte UTF-8 character are
%% all 128 or more: the same as checking its code points, without listing
%% them.
no_control_chars(<<C, _/binary>>) when C < 32; C =:= 127 -> false;
no_control_chars(<<_, Rest/binary>>) -> no_control_chars(Rest);
no_control_chars(<<>>) -> true.

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
