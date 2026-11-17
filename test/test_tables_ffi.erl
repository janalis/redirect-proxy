%% Who owns the application's ETS tables, for tables_test.
-module(test_tables_ffi).

-export([owner/1, heir/1, held_by_an_owner/1, child/2]).

owner(Name) ->
    case ets:info(binary_to_atom(Name), owner) of
        Pid when is_pid(Pid) -> {ok, Pid};
        _ -> {error, nil}
    end.

heir(Name) ->
    case ets:info(binary_to_atom(Name), heir) of
        Pid when is_pid(Pid) -> {ok, Pid};
        _ -> {error, nil}
    end.

held_by_an_owner(Name) ->
    case owner(Name) of
        {ok, Pid} ->
            case erlang:process_info(Pid, dictionary) of
                {dictionary, D} ->
                    proplists:get_value(redirect_proxy_tables_owner, D, false);
                undefined -> false
            end;
        {error, nil} -> false
    end.

%% The child of Supervisor with the id Id (static_supervisor numbers them
%% from 0, in the order they were added).
child(Supervisor, Id) ->
    case lists:keyfind(Id, 1, supervisor:which_children(Supervisor)) of
        {_, Pid, _, _} when is_pid(Pid) -> {ok, Pid};
        _ -> {error, nil}
    end.
