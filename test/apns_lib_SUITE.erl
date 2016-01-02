%%%----------------------------------------------------------------
%%% Purpose: Test suite for the 'apns_lib' module.
%%%-----------------------------------------------------------------

-module(apns_lib_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("apns_recs.hrl").

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

%%--------------------------------------------------------------------
%% Function: suite() -> Info
%%
%% Info = [tuple()]
%%   List of key/value pairs.
%%
%% Description: Returns list of tuples to set default properties
%%              for the suite.
%%
%% Note: The suite/0 function is only meant to be used to return
%% default data values, not perform any other operations.
%%--------------------------------------------------------------------
suite() -> [
        {timetrap, {seconds, 30}}
    ].

%%--------------------------------------------------------------------
%% Function: init_per_suite(Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%%
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%% Reason = term()
%%   The reason for skipping the suite.
%%
%% Description: Initialization before the suite.
%%
%% Note: This function is free to add any key/value pairs to the Config
%% variable, but should NOT alter/remove any existing entries.
%%--------------------------------------------------------------------
init_per_suite(Config) ->
    Config.

%%--------------------------------------------------------------------
%% Function: end_per_suite(Config0) -> void() | {save_config,Config1}
%%
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%%
%% Description: Cleanup after the suite.
%%--------------------------------------------------------------------
end_per_suite(_Config) ->
    ok.

%%--------------------------------------------------------------------
%% Function: init_per_group(GroupName, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%%
%% GroupName = atom()
%%   Name of the test case group that is about to run.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding configuration data for the group.
%% Reason = term()
%%   The reason for skipping all test cases and subgroups in the group.
%%
%% Description: Initialization before each test case group.
%%--------------------------------------------------------------------
init_per_group(_GroupName, Config) ->
    Config.

%%--------------------------------------------------------------------
%% Function: end_per_group(GroupName, Config0) ->
%%               void() | {save_config,Config1}
%%
%% GroupName = atom()
%%   Name of the test case group that is finished.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding configuration data for the group.
%%
%% Description: Cleanup after each test case group.
%%--------------------------------------------------------------------
end_per_group(_GroupName, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% Function: init_per_testcase(TestCase, Config0) ->
%%               Config1 | {skip,Reason} | {skip_and_save,Reason,Config1}
%%
%% TestCase = atom()
%%   Name of the test case that is about to run.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%% Reason = term()
%%   The reason for skipping the test case.
%%
%% Description: Initialization before each test case.
%%
%% Note: This function is free to add any key/value pairs to the Config
%% variable, but should NOT alter/remove any existing entries.
%%--------------------------------------------------------------------
init_per_testcase(_Case, Config) ->
    Config.

%%--------------------------------------------------------------------
%% Function: end_per_testcase(TestCase, Config0) ->
%%               void() | {save_config,Config1} | {fail,Reason}
%%
%% TestCase = atom()
%%   Name of the test case that is finished.
%% Config0 = Config1 = [tuple()]
%%   A list of key/value pairs, holding the test case configuration.
%% Reason = term()
%%   The reason for failing the test case.
%%
%% Description: Cleanup after each test case.
%%--------------------------------------------------------------------
end_per_testcase(_Case, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% Function: groups() -> [Group]
%%
%% Group = {GroupName,Properties,GroupsAndTestCases}
%% GroupName = atom()
%%   The name of the group.
%% Properties = [parallel | sequence | Shuffle | {RepeatType,N}]
%%   Group properties that may be combined.
%% GroupsAndTestCases = [Group | {group,GroupName} | TestCase]
%% TestCase = atom()
%%   The name of a test case.
%% Shuffle = shuffle | {shuffle,Seed}
%%   To get cases executed in random order.
%% Seed = {integer(),integer(),integer()}
%% RepeatType = repeat | repeat_until_all_ok | repeat_until_all_fail |
%%              repeat_until_any_ok | repeat_until_any_fail
%%   To get execution of cases repeated.
%% N = integer() | forever
%%
%% Description: Returns a list of test case group definitions.
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
%% Function: all() -> GroupsAndTestCases | {skip,Reason}
%%
%% GroupsAndTestCases = [{group,GroupName} | TestCase]
%% GroupName = atom()
%%   Name of a test case group.
%% TestCase = atom()
%%   Name of a test case.
%% Reason = term()
%%   The reason for skipping all groups and test cases.
%%
%% Description: Returns the list of groups and test cases that
%%              are to be executed.
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

encode_enhanced_test(doc) ->
    ["apns_lib:encode_enhanced/2 should correctly encode an APNS enhanced notification packet"];
encode_enhanced_test(suite) ->
    [];
encode_enhanced_test(_Config) ->
    ok.

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
    Actual = #apns_notification{} = apns_lib:decode(Packet),
    Expected = shortest_simple_apns_rec(),
    Expected = Actual,
    ok.

roundtrip_enhanced_test(doc) ->
    ["Should correctly roundtrip an APNS enhanced notification packet"];
roundtrip_enhanced_test(suite) ->
    [];
roundtrip_enhanced_test(_Config) ->
    ok.

decode_error_packet_test(doc) ->
    ["Should correctly decode an APNS error notification packet"];
decode_error_packet_test(suite) ->
    [];
decode_error_packet_test(_Config) ->
    Status = 0,
    Id = 12345,
    Packet = make_error_packet(Status, Id),
    Expected = #apns_error{
        id          = Id,
        status      = apns_lib:error_to_atom(Status),
        status_code = Status,
        status_desc = apns_lib:error_description(Status)
    },
    Actual = apns_lib:decode_error_packet(Packet),
    Expected = Actual,
    ok.

decode_bad_error_packet_test(doc) ->
    ["Should handle a APNS error notification packet with an unknown error code"];
decode_bad_error_packet_test(suite) ->
    [];
decode_bad_error_packet_test(_Config) ->
    Status = 250, % Unhandled error code
    Id = 0,
    Packet = make_error_packet(Status, Id),
    Expected = #apns_error{
        id          = Id,
        status      = apns_lib:error_to_atom(Status),
        status_code = Status,
        status_desc = apns_lib:error_description(Status)
    },
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
    #apns_notification{
        token = token_data(),
        payload = alert_json("Test")
    }.

shortest_simple_apns_packet() ->
    Token = token_data(),
    JSON = alert_json("Test"),
    <<0, (bs(Token)):16/big, Token/binary, (bs(JSON)):16/big, JSON/binary>>.

make_error_packet(Status, Id) when is_integer(Status),
                                   Status >= 0, Status =< 255,
                                   is_integer(Id),
                                   Id >= -2147483647, Id =< 2147483647 ->
    <<8, Status, Id:32/integer>>.

