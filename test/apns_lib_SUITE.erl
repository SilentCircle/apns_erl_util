%%%----------------------------------------------------------------
%%% Purpose: Test suite for the 'apns_lib' module.
%%%-----------------------------------------------------------------

-module(apns_lib_SUITE).

-include_lib("common_test/include/ct.hrl").

-compile(export_all).

-define(assertMsg(Cond, Fmt, Args),
    case (Cond) of
        true ->
            ok;
        false ->
            ct:fail("Assertion failed: ~p~n" ++ Fmt, [??Cond] ++ Args)
    end
).

-define(assert(Cond), ?assertMsg((Cond), "", [])).

%%--------------------------------------------------------------------
%% COMMON TEST CALLBACK FUNCTIONS
%%--------------------------------------------------------------------

suite() -> [
        {timetrap, {seconds, 30}}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(_GroupName, Config) ->
    Config.

%%--------------------------------------------------------------------
end_per_group(_GroupName, _Config) ->
    ok.

%%--------------------------------------------------------------------
init_per_testcase(_Case, Config) ->
    Config.

%%--------------------------------------------------------------------
end_per_testcase(_Case, _Config) ->
    ok.

%%--------------------------------------------------------------------
groups() ->
    [
        {
            encode,
            [],
            [
                encode_simple_test,
                encode_enhanced_test,
                roundtrip_simple_test,
                roundtrip_enhanced_test,
                decode_error_packet_test,
                decode_bad_error_packet_test
            ]
        }
    ].

%%--------------------------------------------------------------------
all() ->
    [
        {group, encode}
    ].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------

% t_1(doc) -> ["t/1 should return 0 on an empty list"];
% t_1(suite) -> [];
% t_1(Config) when is_list(Config)  ->
%     ?line 0 = t:foo([]),
%     ok.

%%--------------------------------------------------------------------
encode_simple_test() ->
    [].

encode_simple_test(doc) ->
    ["apns_lib:encode_simple/2 should correctly encode an APNS simple notification packet"];
encode_simple_test(suite) ->
    [];
encode_simple_test(_Config) ->
    Token = token_data(),
    JSON = alert_json("Test"),
    Actual = apns_lib:encode_simple(Token, JSON),
    Expected = shortest_simple_apns_packet(),
    Expected = Actual,
    ok.

%%--------------------------------------------------------------------
encode_enhanced_test(doc) ->
    ["apns_lib:encode_enhanced/2 should correctly encode an APNS enhanced notification packet"];
encode_enhanced_test(suite) ->
    [];
encode_enhanced_test(_Config) ->
    ok.

%%--------------------------------------------------------------------
roundtrip_simple_test() ->
    [].

roundtrip_simple_test(doc) ->
    ["Should correctly roundtrip an APNS simple notification packet"];
roundtrip_simple_test(suite) ->
    [];
roundtrip_simple_test(_Config) ->
    Token = token_data(),
    JSON = alert_json("Test"),
    Packet = apns_lib:encode_simple(Token, JSON),
    Actual = apns_lib:decode(Packet),
    true = apns_recs:'#is_record-'(apns_notification, Actual),
    Expected = shortest_simple_apns_rec(),
    Expected = Actual,
    ok.

%%--------------------------------------------------------------------
roundtrip_enhanced_test(doc) ->
    ["Should correctly roundtrip an APNS enhanced notification packet"];
roundtrip_enhanced_test(suite) ->
    [];
roundtrip_enhanced_test(_Config) ->
    ok.

%%--------------------------------------------------------------------
decode_error_packet_test(doc) ->
    ["Should correctly decode an APNS error notification packet"];
decode_error_packet_test(suite) ->
    [];
decode_error_packet_test(_Config) ->
    Status = 0,
    Id = 12345,
    Packet = make_error_packet(Status, Id),
    Expected = make_apns_error(Status, Id),
    Actual = apns_lib:decode_error_packet(Packet),
    Expected = Actual,
    ok.

%%--------------------------------------------------------------------
decode_bad_error_packet_test(doc) ->
    ["Should handle a APNS error notification packet with an unknown error code"];
decode_bad_error_packet_test(suite) ->
    [];
decode_bad_error_packet_test(_Config) ->
    Status = 250, % Unhandled error code
    Id = 0,
    Packet = make_error_packet(Status, Id),
    Expected = make_apns_error(Status, Id),
    Actual = apns_lib:decode_error_packet(Packet),
    Expected = Actual,
    ok.

%%====================================================================
%% Internal helper functions
%%====================================================================
bs(<<X/binary>>) ->
    byte_size(X).

token_data() ->
    list_to_binary(lists:duplicate(32, 16#FF)).

alert_json(Msg) ->
    jsx:encode([{<<"aps">>,
                [{<<"alert">>, list_to_binary(Msg)},
                 {<<"content-available">>, 1}]}]).

shortest_simple_apns_rec() ->
    apns_recs:'#new-apns_notification'([{token, token_data()},
                                        {payload, alert_json("Test")}]).

shortest_simple_apns_packet() ->
    Token = token_data(),
    JSON = alert_json("Test"),
    <<0, (bs(Token)):16/big, Token/binary, (bs(JSON)):16/big, JSON/binary>>.

make_error_packet(Status, Id) when is_integer(Status),
                                   Status >= 0, Status =< 255,
                                   is_integer(Id),
                                   Id >= -2147483647, Id =< 2147483647 ->
    <<8, Status, Id:32/integer>>.

make_apns_error(Status, Id) ->
    apns_recs:'#new-apns_error'(
                [{id, Id},
                 {status, apns_lib:error_to_atom(Status)},
                 {status_code, Status},
                 {status_desc, apns_lib:error_description(Status)}
                ]).
