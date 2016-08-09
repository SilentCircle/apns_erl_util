#!/usr/bin/env escript
%%! -pa ../_build/default/lib/*/ebin


main(_) ->
    run().

run() ->
    execp({apns_recs, '#exported_records-', []}).

execp({M, F, A} = MFA) ->
    io:format("~s ->\t~p~n~n", [mfa_to_s(MFA), erlang:apply(M, F, A)]).

mfa_to_s({M, F, A}) ->
    io_lib:format("~p:~p(~s)", [M, F, args_to_s(A)]).

args_to_s(Args) ->
    string:join([io_lib:format("~p", [Arg]) || Arg <- Args], ", ").
