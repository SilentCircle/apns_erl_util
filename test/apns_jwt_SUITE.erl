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

% Payload values
-define(TEST_ISS, <<"A566GE4SER">>).

% Header values
-define(JWT_ALG, <<"ES256">>).
-define(JWT_TYP, <<"JWT">>).
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
       verify_test_3,
       verify_test_4,
       test_base64urlcode,
       test_decode_jwt,
       test_decode_jwt_fail
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
    Ctx = make_context(),
    ?TEST_KID = apns_jwt:kid(Ctx).

%%-------------------------------------------------------------------
iss_test(_Config) ->
    Ctx = make_context(),
    ?TEST_ISS = apns_jwt:iss(Ctx).

%%-------------------------------------------------------------------
key_test(_Config) ->
    KID = ?TEST_KID,
    Issuer = ?TEST_ISS,
    SigningKey = apns_jwt:generate_private_key(),
    Ctx = apns_jwt:new(KID, Issuer, SigningKey),
    SigningKey = apns_jwt:key(Ctx).

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

%%-------------------------------------------------------------------
verify_test_3(doc) -> ["Verification should fail"];
verify_test_3(_Config) ->
    KID = ?TEST_KID,
    Issuer = ?TEST_ISS,
    SigningKey = apns_jwt:generate_private_key(),
    JWT = apns_jwt:jwt(KID, Issuer, SigningKey),
    WrongKid = <<"Some wrong kid">>,
    Res = apns_jwt:verify(JWT, WrongKid, Issuer, SigningKey),
    {error, {missing_keys, Ks, bad_items, Bs}} = Res,
    ct:pal("Missing keys: ~p, bad_items: ~p", [Ks, Bs]),
    BadKid = proplists:get_value(<<"kid">>, Bs),
    ?assertMsg(BadKid =/= undefined,
               "BadKid == ~p, WrongKid = ~p", [BadKid, WrongKid]).

%%-------------------------------------------------------------------
verify_test_4(doc) -> ["Verification should fail"];
verify_test_4(_Config) ->
    Enc = fun(EJSON) when is_list(EJSON) ->
                  apns_jwt:base64urlencode(jsx:encode(EJSON));
             (<<Bin/binary>>) ->
                  apns_jwt:base64urlencode(Bin)
          end,

    Sign = fun(Hdr, Payload, Key) ->
                   apns_jwt:sign(jsx:encode(Hdr), jsx:encode(Payload), Key)
           end,

    MakeJWT = fun(Hdr, Payload, Sig) ->
                      list_to_binary([Enc(Hdr), $., Enc(Payload), $.,
                                      Enc(Sig)])
              end,

    GoodHdr = [
               {<<"kid">>, <<"keyid">>},
               {<<"alg">>, <<"RS256">>},
               {<<"typ">>, <<"JWT">>}
              ],
    GoodPayload = [
                   {<<"iss">>, <<"issuer">>},
                   {<<"iat">>, erlang:system_time(seconds)}
                  ],

    BadHdr = [{<<"kid">>, <<"keyid">>}], % missing alg
    BadPayload = [{<<"iss">>, <<"issuer">>}], % missing iat
    BadSig = crypto:rand_bytes(64),

    Key = apns_jwt:generate_private_key(),

    BadHdrJWT = MakeJWT(BadHdr, GoodPayload, Sign(BadHdr, GoodPayload, Key)),
    {error, _} = apns_jwt:verify(BadHdrJWT, <<"keyid">>, <<"issuer">>, Key),
    BadPayloadJWT = MakeJWT(GoodHdr, BadPayload,
                            Sign(GoodHdr, BadPayload, Key)),
    {error, _} = apns_jwt:verify(BadPayloadJWT, <<"keyid">>, <<"issuer">>, Key),
    BadSigJWT = MakeJWT(GoodHdr, GoodPayload, BadSig),
    {error, _} = apns_jwt:verify(BadSigJWT, <<"keyid">>, <<"issuer">>, Key),
    {error, _} = apns_jwt:verify(<<"foobar">>, <<"keyid">>, <<"issuer">>, Key),
    ok = try apns_jwt:verify(junk, <<"keyid">>, <<"issuer">>, Key)
         catch
             error:function_clause ->
                 ok
         end.

%%--------------------------------------------------------------------
test_base64urlcode(_Config) ->
    [B = apns_jwt:base64urldecode(apns_jwt:base64urlencode(B)) ||
     B <- [<<"">>, <<"1">>, <<"12">>, <<"123">>, <<"1234">>]].

%%--------------------------------------------------------------------
test_decode_jwt(_Config) ->
    {<<JWT/binary>>, Ctx} = make_jwt(),
    {Hdr, Payload, Sig, _SigInput} = apns_jwt:decode_jwt(JWT),
    ct:pal("Hdr: ~p, Payload: ~p", [Hdr, Payload]),
    ?TEST_KID = proplists:get_value(<<"kid">>, Hdr),
    ?JWT_ALG = proplists:get_value(<<"alg">>, Hdr),
    ?JWT_TYP = proplists:get_value(<<"typ">>, Hdr),
    ?TEST_ISS = proplists:get_value(<<"iss">>, Payload),
    Iat = proplists:get_value(<<"iat">>, Payload),
    true = is_integer(Iat),
    true = (Iat =< erlang:system_time(seconds) + 3600),
    SigningInput = <<(apns_jwt:base64urlencode(jsx:encode(Hdr)))/binary,
                     $.,
                     (apns_jwt:base64urlencode(jsx:encode(Payload)))/binary>>,
    verify_signature(Sig, SigningInput, apns_jwt:public_key(Ctx)).

%%--------------------------------------------------------------------
test_decode_jwt_fail(_Config) ->
    try apns_jwt:decode_jwt(foo)
    catch
        error:function_clause ->
            ok
    end,
    {error, invalid_jwt} = apns_jwt:decode_jwt(<<>>),
    {error, invalid_jwt} = apns_jwt:decode_jwt(<<"x.y">>),
    {error, invalid_jwt} = apns_jwt:decode_jwt(<<"x.y.z">>).


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
    verify_signature(Sig, Msg, apns_jwt:public_key(Ctx)).

%%--------------------------------------------------------------------
verify_signature(Signature, SigningInput, PublicKey) ->
    ExplicitCurve = crypto:ec_curve(secp256r1),
    {ECPoint, _} = PublicKey,
    Key = [ECPoint#'ECPoint'.point, ExplicitCurve],
    true = crypto:verify(ecdsa, sha256, SigningInput, Signature, Key).

%%--------------------------------------------------------------------
validate_jwt(JWT, KID, Issuer, SigningKey) ->
    validate_jwt(JWT, apns_jwt:new(KID, Issuer, SigningKey)).

%%--------------------------------------------------------------------
make_jwt() ->
    Context = make_context(),
    {apns_jwt:jwt(Context), Context}.

%%--------------------------------------------------------------------
make_context() ->
    KID = ?TEST_KID,
    Issuer = ?TEST_ISS,
    SigningKey = apns_jwt:generate_private_key(),
    apns_jwt:new(KID, Issuer, SigningKey).
