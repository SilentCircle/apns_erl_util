%%%----------------------------------------------------------------
%%% Purpose: Test suite for the 'apns_lib_http2' module.
%%%-----------------------------------------------------------------

-module(apns_lib_http2_SUITE).

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

suite() -> [
        {timetrap, {seconds, 30}}
    ].

init_per_testcase(_Case, Config) ->
    Config.

end_per_testcase(_Case, _Config) ->
    ok.

all() ->
    [
       host_port_prod_test
     , host_port_dev_test
     , host_port_fail_test
     , reason_desc_happy_path_test
     , reason_desc_sad_path_test
     , status_desc_happy_path_test
     , status_desc_sad_path_test
     , make_req_3_happy_path_test
     , make_req_3_sad_path_test1
     , parse_resp_test_200
     , parse_resp_test_410
     , parse_resp_test_400
     , parse_resp_test_5xx
    ].

%%--------------------------------------------------------------------
%% TEST CASES
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% host_port/1
%%--------------------------------------------------------------------
host_port_prod_test(_Config) ->
    Expected = {"api.push.apple.com", 443},
    Actual = apns_lib_http2:host_port(prod),
    Expected = Actual.

host_port_dev_test(_Config) ->
    Expected = {"api.development.push.apple.com", 443},
    Actual = apns_lib_http2:host_port(dev),
    Expected = Actual.

host_port_fail_test(_Config) ->
    try apns_lib_http2:host_port(foo)
    catch error:function_clause -> ok
    end.

%%--------------------------------------------------------------------
%% make_req/3
%%--------------------------------------------------------------------
make_req_3_happy_path_test(_Config) ->
    APNSId = apns_lib_http2:make_uuid(),
    Topic = "com.silentcircle.SilentPhone.voip",
    Expiry = sc_util:posix_time() + 86400,
    Priority = 10,
    TestOpts = [
                [], % No opts

                [{uuid, b(APNSId)}],

                [{uuid, b(APNSId)},
                 {topic, b(Topic)}],

                [{uuid, b(APNSId)},
                 {topic, b(Topic)},
                 {expiration, b(Expiry)}],

                [{uuid, b(APNSId)},
                 {topic, b(Topic)},
                 {expiration, b(Expiry)},
                 {priority, b(Priority)}]
               ],

    [do_req_test(Opts) || Opts <- TestOpts].

%%--------------------------------------------------------------------
make_req_3_sad_path_test1(_Config) ->
    BadOpt = {some_crap, foo},
    try do_req_test([BadOpt])
    catch throw:{unsupported_apns_opt, BadOpt} -> ok
    end.

%%--------------------------------------------------------------------
%% parse_resp/1
%%--------------------------------------------------------------------
parse_resp_test_200(_Config) ->
    Id = apns_lib_http2:make_uuid(),
    Status = <<"200">>,
    StatusDesc = <<"Success">>,
    Reason = undefined,
    Timestamp = undefined,
    Resp = make_resp(Id, Status, Reason, Timestamp),
    PL = apns_lib_http2:parse_resp(Resp),
    validate_resp(PL, Id, Status, StatusDesc, Timestamp).

parse_resp_test_410(_Config) ->
    Id = apns_lib_http2:make_uuid(),
    Status = <<"410">>,
    Timestamp = 1458114061260,
    Reason = <<"Unregistered">>,
    Resp = make_resp(Id, Status, Reason, Timestamp),
    PL = apns_lib_http2:parse_resp(Resp),
    StatusDesc = <<"The device token is no longer active for the topic.">>,
    validate_resp(PL, Id, Status, StatusDesc, Timestamp),
    TSDesc = <<"2016-03-16T07:41:01Z">>,
    TSDesc = val(timestamp_desc, PL).

parse_resp_test_400(_Config) ->
    Id = apns_lib_http2:make_uuid(),
    Status = <<"400">>,
    Timestamp = undefined,
    Reason = <<"Unregistered">>,
    Resp = make_resp(Id, Status, Reason, Timestamp),
    PL = apns_lib_http2:parse_resp(Resp),
    StatusDesc = <<"Bad request">>,
    validate_resp(PL, Id, Status, StatusDesc, Timestamp).

parse_resp_test_5xx(_Config) ->
    Id = apns_lib_http2:make_uuid(),
    Status = <<"510">>,
    Timestamp = undefined,
    Reason = <<"Unknown server issue">>,
    Resp = make_resp(Id, Status, Reason, Timestamp),
    PL = apns_lib_http2:parse_resp(Resp),
    StatusDesc = <<"Unknown status 510">>,
    validate_resp(PL, Id, Status, StatusDesc, Timestamp).

%%--------------------------------------------------------------------
%% reason_desc/1
%%--------------------------------------------------------------------
reason_desc_happy_path_test(_Config) ->
    [RsnDesc = apns_lib_http2:reason_desc(Rsn)
     || {Rsn, RsnDesc} <- reasons()],

    Other = <<"SomeOtherReason">>,
    Other = apns_lib_http2:reason_desc(Other).

reason_desc_sad_path_test(_Config) ->
    try apns_lib_http2:reason_desc({oops})
    catch error: function_clause -> ok
    end.

status_desc_happy_path_test(_Config) ->
    [StsDesc = apns_lib_http2:status_desc(Sts)
     || {Sts, StsDesc} <- statuses()],

    <<"Unknown status 510">> = apns_lib_http2:status_desc(<<"510">>).

status_desc_sad_path_test(_Config) ->
    try apns_lib_http2:status_desc({oops})
    catch error: function_clause -> ok
    end.

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%%
%%--------------------------------------------------------------------

statuses() ->
    [
     {<<"200">>,
      <<"Success">>},
     {<<"400">>,
      <<"Bad request">>},
     {<<"403">>,
      <<"There was an error with the certificate.">>},
     {<<"405">>,
      <<
        "The request used a bad :method value. Only POST requests are "
        "supported."
      >>},
     {<<"410">>,
      <<"The device token is no longer active for the topic.">>},
     {<<"413">>,
      <<"The notification payload was too large.">>},
     {<<"429">>,
      <<"The server received too many requests for the same device token.">>},
     {<<"500">>,
      <<"Internal server error">>},
     {<<"503">>,
      <<"The server is shutting down and unavailable.">>}
    ].

reasons() ->
    [
     {<<"PayloadEmpty">>,
      <<"The message payload was empty.">>},
     {<<"PayloadTooLarge">>,
      <<"The message payload was too large. The maximum payload size is 4096 "
        "bytes.">>},
     {<<"BadTopic">>,
      <<"The apns-topic was invalid.">>},
     {<<"TopicDisallowed">>,
      <<"Pushing to this topic is not allowed.">>},
     {<<"BadMessageId">>,
      <<"The apns-id value is bad.">>},
     {<<"BadExpirationDate">>,
      <<"The apns-expiration value is bad.">>},
     {<<"BadPriority">>,
      <<"The apns-priority value is bad.">>},
     {<<"MissingDeviceToken">>,
      <<"The device token is not specified in the request :path. Verify that "
        "the :path header contains the device token.">>},
     {<<"BadDeviceToken">>,
      <<
        "The specified device token was bad. Verify that the request contains "
        "a valid token and that the token matches the environment."
      >>},
     {<<"DeviceTokenNotForTopic">>,
      <<"The device token does not match the specified topic.">>},
     {<<"Unregistered">>,
      <<"The device token is inactive for the specified topic.">>},
     {<<"DuplicateHeaders">>,
      <<"One or more headers were repeated.">>},
     {<<"BadCertificateEnvironment">>,
      <<"The client certificate was for the wrong environment.">>},
     {<<"BadCertificate">>,
      <<"The certificate was bad.">>},
     {<<"Forbidden">>,
      <<"The specified action is not allowed.">>},
     {<<"BadPath">>,
      <<"The request contained a bad :path value.">>},
     {<<"MethodNotAllowed">>,
      <<"The specified :method was not POST.">>},
     {<<"TooManyRequests">>,
      <<"Too many requests were made consecutively to the same device token.">>},
     {<<"IdleTimeout">>,
      <<"Idle time out.">>},
     {<<"Shutdown">>,
      <<"The server is shutting down.">>},
     {<<"InternalServerError">>,
      <<"An internal server error occurred.">>},
     {<<"ServiceUnavailable">>,
      <<"The service is unavailable.">>},
     {<<"MissingTopic">>,
      <<
        "The apns-topic header of the request was not specified and was "
        "required. The apns-topic header is mandatory when the client is "
        "connected using a certificate that supports multiple topics."
      >>}
    ].

reason_desc(<<Other/bytes>>) ->
    Other.


%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------
do_req_test(Opts) ->
    Token = rand_tok(),
    JSON = make_nfn(),
    {Hdrs, Body} = apns_lib_http2:make_req(Token, JSON, Opts),
    validate_http2_req(Hdrs, Body, Token, JSON, Opts).


validate_http2_req(Hdrs, Body, Token, JSON, Opts) ->
    Path = sc_util:to_bin("/3/device/" ++ Token),
    Path = val(<<":path">>, Hdrs),

    Method = val(<<":method">>, Hdrs),
    Method = <<"POST">>,

    Scheme = val(<<":scheme">>, Hdrs),
    Scheme = <<"https">>,

    maybe_validate(uuid, Opts, <<"apns-id">>, Hdrs),
    maybe_validate(topic, Opts, <<"apns-topic">>, Hdrs),
    maybe_validate(expiration, Opts, <<"apns-expiration">>, Hdrs),
    maybe_validate(priority, Opts, <<"apns-priority">>, Hdrs),
    Body = sc_util:to_bin(JSON).

maybe_validate(OptKey, Opts, HdrKey, Hdrs) ->
    case lists:keyfind(OptKey, 1, Opts) of
        false ->
            ok;
        {_, OptVal} ->
            Val = val(HdrKey, Hdrs),
            ct:pal("OptVal=~w, Val=~w", [OptVal, Val]),
            OptVal = Val
    end.

val(K, PL) ->
    case lists:keyfind(K, 1, PL) of
        false ->
            ct:fail("Expected key ~p not found\n", [K]);
        {_, V} ->
            V
    end.

rand_tok() ->
    sc_util:bitstring_to_hex(crypto:rand_bytes(32)).

make_nfn() ->
    Nfn = [
           {'alert', <<"Would you like to play a game?">>},
           {'badge', 1},
           {'sound', <<"wopr">>}
          ],
    apns_json:make_notification(Nfn).

make_resp(Id, Status, Reason, Timestamp) ->
    RespHdrs = [{<<"apns-id">>, b(Id)},
                {<<":status">>, b(Status)}],
    RespBody = case Status of
                   <<"200">> ->
                       [];
                   <<"410">> when is_integer(Timestamp),
                                  Reason /= undefined ->
                       EJSON = [{<<"reason">>, b(Reason)},
                                {<<"timestamp">>, Timestamp}],
                       [jsx:encode(EJSON)];
                   _ when Reason /= undefined ->
                       [jsx:encode([{<<"reason">>, b(Reason)}])]
               end,
    {RespHdrs, RespBody}.


validate_resp(PL, Id, Status, StatusDesc, Timestamp) ->
    Id = val(uuid, PL),
    Status = val(status, PL),
    StatusDesc = val(status_desc, PL),
    case Status of
        <<"200">> ->
            ok;
        _ ->
            Reason = val(reason, PL),
            ReasonDesc = apns_lib_http2:reason_desc(Reason),
            ReasonDesc = val(reason_desc, PL),
            case Status of
                <<"410">> ->
                    RE = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z",
                    Reason = <<"Unregistered">>,
                    Timestamp = val(timestamp, PL),
                    true = is_integer(Timestamp),
                    TimestampDesc = val(timestamp_desc, PL),
                    TimestampDesc = apns_lib_http2:timestamp_desc(Timestamp),
                    {match, _} = re:run(TimestampDesc, RE);
                _ ->
                    ok
            end
    end.

-compile({inline, [{b, 1}]}).
b(X) -> sc_util:to_bin(X).

timestamp() ->
    erlang:system_time(milli_seconds).

