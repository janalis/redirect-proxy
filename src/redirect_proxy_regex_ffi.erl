%% Regular expressions with a backtracking budget (ReDoS guard).
-module(redirect_proxy_regex_ffi).

-export([
    count_regex_limit/0, reductions/0, regex_compile/2, regex_limit_count/0,
    regex_limit_init/0, regex_run/2
]).

-define(MATCH_LIMIT, 100000).

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
