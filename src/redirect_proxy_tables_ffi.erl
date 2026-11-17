%% The owner of the long-lived ETS tables (sessions, rate limits, OIDC
%% flows, tokens, the rules in effect, the checkers, the file memo and the
%% access log time cache). A table is deleted with the process that created
%% it: this one does nothing else, so that it does not die with a store,
%% a listener or the process that started the application.
%%
%% Several applications may run in one VM (the tests): the tables are named,
%% so the first owner creates them and the others find them. Each later
%% owner asks the one holding the tables to make it their heir (`ets`
%% `heir`), so that they pass to it, not away, when that owner stops first.
%% If that owner dies before it could, the tables are created again.
-module(redirect_proxy_tables_ffi).

-export([start_link/1, init/2]).

%% in the process dictionary of every owner
-define(MARK, redirect_proxy_tables_owner).

%% {ok, Pid} | {error, Reason}. Create() creates the tables in the calling
%% process (a table that exists is left as it is).
start_link(Create) ->
    proc_lib:start_link(?MODULE, init, [self(), Create]).

init(Parent, Create) ->
    put(?MARK, true),
    Watched = settle(Create, #{}),
    proc_lib:init_ack(Parent, {ok, self()}),
    loop(Create, Watched).

loop(Create, Watched) ->
    receive
        {heir, From, Ref} ->
            Heir = {heir, From, inherited},
            _ = [try ets:setopts(T, Heir) catch error:badarg -> ok end
                 || T <- ets:all(), is_ours(T),
                    ets:info(T, owner) =:= self()],
            From ! {Ref, ok},
            loop(Create, Watched);
        {'DOWN', _, process, Pid, _} ->
            %% its tables passed to their heir, or were deleted
            loop(Create, settle(Create, maps:remove(Pid, Watched)));
        _ ->
            %% 'ETS-TRANSFER' when this process inherits tables
            loop(Create, Watched)
    end.

%% Creates the missing tables, and watches the other processes owning some
%% of them, to create them again when they stop: another owner is asked to
%% make this process its heir (then they pass to it instead). Another
%% process (a test that created a table) has its tables deleted with it.
%% `Watched`: the processes watched.
settle(Create, Watched) ->
    Create(),
    Owners = lists:usort([Owner || T <- ets:all(), is_ours(T),
                                   Owner <- [ets:info(T, owner)],
                                   is_pid(Owner), Owner =/= self(),
                                   not maps:is_key(Owner, Watched)]),
    lists:foldl(fun(Owner, Acc) ->
        _ = monitor(process, Owner),
        case is_owner(Owner) of
            true -> Owner ! {heir, self(), make_ref()};
            false -> ok
        end,
        Acc#{Owner => true}
    end, Watched, Owners).

%% The application's tables are named redirect_proxy_*.
is_ours(T) when is_atom(T) ->
    lists:prefix("redirect_proxy_", atom_to_list(T));
is_ours(_) ->
    false.

is_owner(Pid) ->
    case erlang:process_info(Pid, dictionary) of
        {dictionary, Dictionary} ->
            proplists:get_value(?MARK, Dictionary, false);
        undefined -> false
    end.
