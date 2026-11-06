%% logger formatter writing the application log as JSON lines:
%% {"time": RFC 3339 UTC, "level": ..., "msg": ..., "domain": "a.b"}.
%% Used for the default handler with log.format = "json".
-module(redirect_proxy_log_json).
-export([format/2, use/0]).

use() ->
    _ = logger:set_handler_config(default, formatter, {?MODULE, #{}}),
    nil.

format(#{level := Level, msg := Msg, meta := Meta}, _Config) ->
    Time = maps:get(time, Meta, logger:timestamp()),
    Fields0 = #{
        time => list_to_binary(calendar:system_time_to_rfc3339(
                    Time, [{unit, microsecond}, {offset, "Z"}])),
        level => atom_to_binary(Level),
        msg => message(Msg)
    },
    Fields = case Meta of
        #{domain := Domain} when is_list(Domain), Domain =/= [] ->
            Fields0#{domain => iolist_to_binary(
                lists:join(".", [atom_to_binary(D) || D <- Domain]))};
        _ -> Fields0
    end,
    [json:encode(Fields), $\n].

message({string, Chardata}) -> unicode:characters_to_binary(Chardata);
message({report, Report}) -> unicode:characters_to_binary(io_lib:format("~0tp", [Report]));
message({Format, Args}) -> unicode:characters_to_binary(io_lib:format(Format, Args)).
