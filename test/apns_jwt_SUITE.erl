%%%----------------------------------------------------------------
%%% Purpose: Test suite for the 'apns_jwt' module.
%%%-----------------------------------------------------------------

-module(apns_jwt_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

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
-define(TEST_ISS, <<"A566GE4SER">>).
-define(TEST_KID, <<"ATestKeyId">>).

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
      jwt,
      [],
      [
       jwt_test1,
       jwt_test2,
       new_test,
       kid_test,
       iss_test,
       key_test,
       verify_test_1,
       verify_test_2,
       test_base64urlcode
      ]
     }
    ].

%%--------------------------------------------------------------------
all() ->
    [
        {group, jwt}
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
jwt_test1(doc) -> ["jwt/1 should return valid JWT"];
jwt_test1(Config) when is_list(Config)  ->
    {JWT, Context} = make_jwt(),
    validate_jwt(JWT, Context).

%%--------------------------------------------------------------------
jwt_test2(doc) -> ["jwt/3 should return valid JWT"];
jwt_test2(Config) when is_list(Config)  ->
    KID = ?TEST_KID,
    Issuer = ?TEST_ISS,
    SigningKey = apns_jwt:generate_private_key(),
    JWT = apns_jwt:jwt(KID, Issuer, SigningKey),
    validate_jwt(JWT, KID, Issuer, SigningKey).

%%-------------------------------------------------------------------
new_test(_Config) ->
    KID = ?TEST_KID,
    Issuer = ?TEST_ISS,
    SigningKey = apns_jwt:generate_private_key(),
    apns_jwt:new(KID, Issuer, SigningKey).

%%-------------------------------------------------------------------
kid_test(_Config) ->
    ok.

%%-------------------------------------------------------------------
iss_test(_Config) ->
    ok.

%%-------------------------------------------------------------------
key_test(_Config) ->
    ok.

%%-------------------------------------------------------------------
verify_test_1(_Config) ->
    {JWT, Context} = make_jwt(),
    ok = apns_jwt:verify(JWT, Context),
    validate_jwt(JWT, Context).

%%-------------------------------------------------------------------
verify_test_2(_Config) ->
    {JWT, Context} = make_jwt(),
    ok = apns_jwt:verify(JWT, ?TEST_KID, ?TEST_ISS, apns_jwt:key(Context)),
    validate_jwt(JWT, Context).

%%--------------------------------------------------------------------
test_base64urlcode(_Config) ->
    [B = apns_jwt:base64urldecode(apns_jwt:base64urlencode(B)) ||
     B <- [<<"">>, <<"1">>, <<"12">>, <<"123">>, <<"1234">>]].

%%====================================================================
%% Internal helper functions
%%====================================================================
generate_ec_keypair() ->
    ECPrivateKey = apns_jwt:generate_private_key(),
    ECPublicKey = apns_jwt:public_key(ECPrivateKey),
    {ECPublicKey, ECPrivateKey}.

%%--------------------------------------------------------------------
validate_jwt(Jwt, Ctx) ->
    [EncHdr, EncMsg, EncSig] = binary:split(Jwt, <<$.>>, [global]),
    Msg = <<EncHdr/binary, $., EncMsg/binary>>,
    Sig = apns_jwt:base64urldecode(EncSig),
    ExplicitCurve = crypto:ec_curve(secp256r1),
    {ECPoint, _} = apns_jwt:public_key(Ctx),
    Key = [ECPoint#'ECPoint'.point, ExplicitCurve],
    true = crypto:verify(ecdsa, sha256, Msg, Sig, Key).

%%--------------------------------------------------------------------
validate_jwt(JWT, KID, Issuer, SigningKey) ->
    validate_jwt(JWT, apns_jwt:new(KID, Issuer, SigningKey)).

%%--------------------------------------------------------------------
make_jwt() ->
    KID = ?TEST_KID,
    Issuer = ?TEST_ISS,
    SigningKey = apns_jwt:generate_private_key(),
    Context = apns_jwt:new(KID, Issuer, SigningKey),
    {apns_jwt:jwt(Context), Context}.
