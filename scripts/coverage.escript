#!/usr/bin/env escript
%%! -noshell
%% Runs the test suite under Erlang's `cover` tool and reports line coverage
%% of the application modules.
%%
%% Gleam has no native coverage tool: modules are compiled to Erlang first,
%% so coverage is measured on the generated Erlang code, then summarised per
%% Gleam module. Line numbers in the LCOV report refer to the generated .erl
%% files in build/dev/erlang/redirect_proxy/_gleam_artefacts.
%%
%% Usage: escript scripts/coverage.escript [MIN_PERCENT]
%% Writes coverage/lcov.info and coverage/summary.txt.

main(Args) ->
    Min = case Args of
        [M | _] -> list_to_integer(M);
        [] -> 0
    end,
    Root = filename:absname("build/dev/erlang"),
    [code:add_patha(D) || D <- filelib:wildcard(filename:join(Root, "*/ebin"))],
    Ebin = filename:join([Root, "redirect_proxy", "ebin"]),
    Artefacts = filename:join([Root, "redirect_proxy", "_gleam_artefacts"]),
    {ok, _} = cover:start(),
    AllModules = [list_to_atom(filename:basename(F, ".beam"))
                  || F <- filelib:wildcard(filename:join(Ebin, "*.beam"))],
    {Tests, App} = lists:partition(fun is_test_module/1, AllModules),
    [ok = compile(Mod, Ebin) || Mod <- App],
    _ = application:ensure_all_started(redirect_proxy),
    logger:set_primary_config(level, critical),
    TestModules = [M || M <- Tests, lists:suffix("_test", atom_to_list(M)),
                        M =/= redirect_proxy_test],
    %% Instrumented code is slower: give every test a generous timeout.
    TestFuns = [{timeout, 300, {M, F}}
                || M <- TestModules,
                   {F, 0} <- M:module_info(exports),
                   lists:suffix("_test", atom_to_list(F))],
    Result = eunit:test(TestFuns, [{print_depth, 5}]),
    Rows = [analyse(Mod) || Mod <- App],
    ok = filelib:ensure_dir("coverage/"),
    write_lcov("coverage/lcov.info", Rows, Artefacts),
    Summary = summary(Rows),
    ok = file:write_file("coverage/summary.txt", Summary),
    io:put_chars(Summary),
    Total = total(Rows),
    cover:stop(),
    case {Result, Total >= Min} of
        {ok, true} -> halt(0);
        {ok, false} ->
            io:format("~ncoverage ~.1f% is below the required ~B%~n", [Total, Min]),
            halt(2);
        _ -> halt(1)
    end.

compile(Mod, Ebin) ->
    case cover:compile_beam(filename:join(Ebin, atom_to_list(Mod) ++ ".beam")) of
        {ok, _} -> ok;
        {error, Reason} ->
            io:format("cannot instrument ~p: ~p~n", [Mod, Reason]),
            ok
    end.

%% Test modules, the generated entry point and modules made only of
%% `@external` declarations are not measured.
is_test_module(Mod) ->
    Name = atom_to_list(Mod),
    lists:suffix("_test", Name) orelse Name =:= "support"
        orelse Name =:= "test_jwt_ffi" orelse Name =:= "redirect_proxy_test"
        orelse lists:suffix("@@main", Name)
        orelse Name =:= "redirect_proxy@ffi".

analyse(Mod) ->
    case cover:analyse(Mod, calls, line) of
        {ok, Lines} ->
            Executable = [{L, C} || {{_, L}, C} <- Lines, L > 0],
            Covered = length([x || {_, C} <- Executable, C > 0]),
            {Mod, Covered, length(Executable), Executable};
        _ -> {Mod, 0, 0, []}
    end.

total(Rows) ->
    {C, T} = lists:foldl(fun({_, C0, T0, _}, {C1, T1}) -> {C0 + C1, T0 + T1} end,
                         {0, 0}, Rows),
    case T of 0 -> 100.0; _ -> 100 * C / T end.

summary(Rows) ->
    Sorted = lists:keysort(1, Rows),
    Lines = [io_lib:format("~6.1f%  ~5B/~-5B  ~s~n",
                           [pct(C, T), C, T, gleam_name(M)])
             || {M, C, T, _} <- Sorted, T > 0],
    [io_lib:format("~nLine coverage (generated Erlang, per Gleam module)~n~n", []),
     Lines,
     io_lib:format("~n~6.1f%  total~n", [total(Rows)])].

pct(_, 0) -> 100.0;
pct(C, T) -> 100 * C / T.

gleam_name(Mod) ->
    string:replace(atom_to_list(Mod), "@", "/", all).

write_lcov(Path, Rows, Artefacts) ->
    Records = [[io_lib:format("TN:~nSF:~s~n", [filename:join(Artefacts, atom_to_list(M) ++ ".erl")]),
                [io_lib:format("DA:~B,~B~n", [L, N]) || {L, N} <- lists:usort(Lines)],
                io_lib:format("LF:~B~nLH:~B~nend_of_record~n", [T, C])]
               || {M, C, T, Lines} <- Rows, T > 0],
    ok = file:write_file(Path, Records).
