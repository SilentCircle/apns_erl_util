%%% ==========================================================================
%%% Copyright 2015 Silent Circle
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%% ==========================================================================

%%%-------------------------------------------------------------------
%%% @author Edwin Fine <efine@silentcircle.com>
%%% @copyright 2016 Silent Circle
%%% @doc This module supports the creation and validation of APNS
%%% authorization tokens (JWTs).
%%% @end
%%%-------------------------------------------------------------------
-module(apns_jwt).

-export([
         base64urldecode/1,
         base64urlencode/1,
         decode_jwt/1,
         generate_private_key/0,
         get_private_key/1,
         jwt/1,
         jwt/3,
         iss/1,
         key/1,
         kid/1,
         named_curve/0,
         new/3,
         public_key/1,
         sign/3,
         verify/2,
         verify/4,
         verify_jwt/2
        ]).

-export_type([
              alg/0,
              base64_urlencoded/0,
              bstring/0,
              context/0,
              ec_private_key/0,
              iat/0,
              iss/0,
              jose_header/0,
              json/0,
              jws_payload/0,
              jws_signature/0,
              jws_signing_input/0,
              jwt/0,
              kid/0,
              pem_encoded_key/0,
              posix_time/0,
              signing_key/0
             ]).

-include_lib("public_key/include/public_key.hrl").

-define(JWT_ALG, <<"ES256">>).
-define(JWT_TYP, <<"JWT">>).
-define(DIGEST_TYPE, sha256).
-define(MAX_IAT_AGE_SECS, 60*60). % APNS gives it an hour

-define(IS_SIGNING_KEY(SigningKey),
        (is_binary(SigningKey) orelse is_record(SigningKey, 'ECPrivateKey'))).

%%%-------------------------------------------------------------------
%%% Types
%%%-------------------------------------------------------------------
-type bstring() :: binary().
-type base64_urlencoded() :: bstring().
-type digest_type() :: atom().
-type json() :: jsx:json_text().
-type posix_time() :: pos_integer().
-type alg() :: bstring().
-type iat() :: posix_time().
-type iss() :: bstring().
-type kid() :: bstring().
-type jose_header() :: json().
-type jws_payload() :: json().
-type jws_signature() :: base64_urlencoded().
-type jws_signing_input() :: bstring().
-type jwt() :: bstring().
-type pem_encoded_key() :: bstring().
-type ec_private_key() :: #'ECPrivateKey'{}.
-type signing_key() :: pem_encoded_key() | ec_private_key().

-record(apns_jwt_ctx,
        {kid                   :: bstring(),
         iss                   :: bstring(),
         digest = ?DIGEST_TYPE :: digest_type(),
         key                   :: ec_private_key(),
         enc_hdr               :: base64_urlencoded() % JWT header JSON
        }).

-type apns_jwt_ctx() :: #apns_jwt_ctx{}.
-type output_context() :: binary().
-type input_context() :: output_context() | apns_jwt_ctx().
-opaque context() :: output_context().

%%%====================================================================
%%% API
%%%====================================================================
%%--------------------------------------------------------------------
%% @doc Create a JWT for APNS usage, using the current erlang system time.
%% This is signed with ECDSA using the P-256 curve and the ES256 algorithm.
%%
%% === Parameters ===
%%
%% <dl>
%%   <dd>`KID :: binary()'</dd>
%%   <dt>This is the key ID of the private APNS key downloaded from the Apple
%%   developer portal.</dt>
%%   <dd>`Issuer :: binary()'</dd>
%%   <dt>This is the Apple Team ID from the Apple developer portal.</dt>
%%   <dd>`SigningKey :: signing_key()'</dd>
%%   <dt>This is the private key downloaded from the Apple
%%   developer portal, either PEM-encoded as downloaded, or as
%%   an `` #'ECPrivateKey{}' '' record.</dt>
%% </dl>
%% @end
%%-------------------------------------------------------------------
-spec jwt(KID, Issuer, SigningKey) -> JWT when
      KID :: kid(), Issuer :: iss(), SigningKey :: signing_key(), JWT :: jwt().
jwt(KID, Issuer, SigningKey) when is_binary(KID) andalso
                                  is_binary(Issuer) andalso
                                  ?IS_SIGNING_KEY(SigningKey) ->
    jwt(new(KID, Issuer, SigningKey)).

%%--------------------------------------------------------------------
%% @equiv jwt
%% @end
%%-------------------------------------------------------------------
-spec jwt(Context) -> JWT when Context :: input_context(), JWT :: jwt().
jwt(<<Context/binary>>) ->
    jwt(binary_to_term(Context));
jwt(#apns_jwt_ctx{}=Context) ->
    SigningInput = signing_input(Context),
    Signature = signature(SigningInput, key(Context)),
    <<SigningInput/binary, $., Signature/binary>>.

%%--------------------------------------------------------------------
%% @doc Create a signing context from the parameters passed. This can
%% be used later to create a JWT.
%%
%% === Parameters ===
%%
%% <dl>
%%   <dd>`KID :: binary()'</dd>
%%   <dt>This is the key ID of the private APNS key downloaded from the Apple
%%   developer portal.</dt>
%%   <dd>`Issuer :: binary()'</dd>
%%   <dt>This is the Apple Team ID from the Apple developer portal.</dt>
%%   <dd>`SigningKey :: signing_key()'</dd>
%%   <dt>This is the PEM-encoded private key downloaded from the Apple
%%   developer portal.</dt>
%% </dl>
%% @end
%%-------------------------------------------------------------------
-spec new(KID, Issuer, SigningKey) -> Context when
      KID :: kid(), Issuer :: iss(), SigningKey :: signing_key(),
      Context :: context().
new(KID, Issuer, SigningKey) when is_binary(KID) andalso
                                  is_binary(Issuer) andalso
                                  ?IS_SIGNING_KEY(SigningKey) ->
    internal_to_ctx(make_internal(KID, Issuer, SigningKey)).

%%-------------------------------------------------------------------
%% @doc Accessor for kid.
-spec kid(Context) -> KID when
      Context :: input_context(), KID :: kid().
kid(<<Context/binary>>) ->
    kid(ctx_to_internal(Context));
kid(#apns_jwt_ctx{kid=KID}) ->
    KID.

%%-------------------------------------------------------------------
%% @doc Accessor for iss.
-spec iss(Context) -> Iss when
      Context :: input_context(), Iss :: iss().
iss(<<Context/binary>>) ->
    iss(ctx_to_internal(Context));
iss(#apns_jwt_ctx{iss=Iss}) ->
    Iss.

%%-------------------------------------------------------------------
%% @doc Accessor for key.
-spec key(Context) -> Key when
      Context :: input_context(), Key :: signing_key().
key(<<Context/binary>>) ->
    key(ctx_to_internal(Context));
key(#apns_jwt_ctx{key=Key}) ->
    Key.

%%--------------------------------------------------------------------
%% @doc Transform a pem-encoded PKCS8 binary to a private key structure.
%% @end
%%--------------------------------------------------------------------
-spec get_private_key(SigningKeyPem) -> PrivateKey when
      SigningKeyPem :: pem_encoded_key(), PrivateKey :: ec_private_key().
get_private_key(SigningKeyPem) ->
    [PemEntry] = public_key:pem_decode(SigningKeyPem),
    %% -record('PrivateKeyInfo',{version, privateKeyAlgorithm,
    %%         privateKey, attributes}).
    PrivateKeyInfo = public_key:pem_entry_decode(PemEntry),

    %% So this isn't the end of it - the privateKey component of
    %% 'PrivateKeyInfo' is just an OCTET-STRING that needs to be further
    %% decoded as an ECPrivateKey.
    PrivKeyOctets = PrivateKeyInfo#'PrivateKeyInfo'.privateKey,
    %% -record('ECPrivateKey', {version, privateKey, parameters, publicKey}).
    {ok, ECPrivateKey} = 'OTP-PUB-KEY':decode('ECPrivateKey', PrivKeyOctets),
    ECPrivateKey.

%%--------------------------------------------------------------------
%% @doc Generate a private key. This is mostly useful for testing.
-spec generate_private_key() -> ec_private_key().
generate_private_key() ->
    public_key:generate_key(named_curve()).

%%--------------------------------------------------------------------
%% @doc Extract an EC public key from context or private key.
-spec public_key(Opaque) -> PublicKey when
      Opaque :: ec_private_key() | input_context(),
      PublicKey :: {#'ECPoint'{}, {'namedCurve', tuple()}}.
public_key(#'ECPrivateKey'{publicKey=ECPK}) ->
    {#'ECPoint'{point=ECPK}, apns_jwt:named_curve()};
public_key(#apns_jwt_ctx{key=#'ECPrivateKey'{}=Key}) ->
    public_key(Key);
public_key(<<Context/binary>>) ->
    public_key(ctx_to_internal(Context)).

%%--------------------------------------------------------------------
%% @doc Sign a JWT given the JSON header and payload, and the private key.
%% The header and payload must not be base64urlencoded.
%% @end
%%-------------------------------------------------------------------
-spec sign(JsonHdr, JsonPayload, Key) -> Result when
      JsonHdr :: jose_header(), JsonPayload :: jws_payload(),
      Key :: ec_private_key(), Result :: jws_signature().
sign(<<JsonHdr/binary>>, <<JsonPayload/binary>>, #'ECPrivateKey'{}=Key) ->
    try {jsx:decode(JsonHdr), jsx:decode(JsonPayload)} of
        {[{_,_}|_], [{_, _}|_]} ->
            Msg = signing_input_hp(base64urlencode(JsonHdr),
                                   base64urlencode(JsonPayload)),
            signature(Msg, Key);
        _ ->
            {error, invalid_data}
    catch
        error:badarg ->
            {error, invalid_json}
    end.

%%-------------------------------------------------------------------
%% @doc Verify a JWT using a context.
%% Return `ok' on success, and one of
%% `{error, {jwt_validation_failed, [Key :: binary()]}}' or
%%
%% ```
%% {error, {missing_keys, [Key :: binary()],
%%          bad_items, [{Key :: binary(), Val :: any()}]}}
%% '''
%%
%% if an error occurred.
-spec verify(JWT, Ctx) -> Result when
      JWT :: jwt(), Ctx :: input_context(),
      Result :: ok | {error, Reason}, Reason :: term().
verify(<<JWT/binary>>, <<Ctx/binary>>) ->
    verify(JWT, ctx_to_internal(Ctx));
verify(<<JWT/binary>>, #apns_jwt_ctx{}=Ctx) ->
    case decode_jwt(JWT) of
        {_Hdr, _Payload, _Sig, _SigInput}=Parts ->
            verify_jwt(Parts, Ctx);
        {error, _Reason}=Error ->
            Error
    end.

%%-------------------------------------------------------------------
%% @doc Verify a JWT using the kid, iss, and signing key.
%% @see verify/2
-spec verify(JWT, KID, Iss, SigningKey) -> Result when
      JWT :: jwt(), KID :: kid(), Iss :: iss(), SigningKey:: signing_key(),
      Result :: ok | {error, Reason}, Reason :: term().
verify(JWT, KID, Iss, SigningKey) ->
    verify(JWT, make_internal(KID, Iss, SigningKey)).

%%--------------------------------------------------------------------
%% @doc
%% Verify a JWT as decoded by `decode_jwt/1'.
%% @end
%%--------------------------------------------------------------------
-spec verify_jwt({Hdr, Payload, Sig, SigInput}, Ctx) -> Result when
      Hdr :: jsx:json_term(), Payload :: jsx:json_term(),
      Sig :: binary(), SigInput :: binary(), Ctx :: input_context(),
      Result :: ok
              | {error, {jwt_validation_failed, signature}}
              | {error, {missing_keys, Ks, bad_items, Bs}},
      Ks :: [KeyName :: binary()], Bs :: [{KeyName :: binary(), Val :: any()}].
verify_jwt({Hdr, Payload, Sig, SigInput}, Ctx) ->
    case {verify_jwt_hdr(Hdr, Ctx),
          verify_jwt_payload(Payload, Ctx)} of
        {ok, ok} ->
            case verify_signature(Sig, SigInput, Ctx) of
                true ->
                    ok;
                false ->
                    {error, {jwt_validation_failed, signature}}
            end;
        {HdrErr, PayloadErr} ->
            combine_errors([HdrErr, PayloadErr])
    end.

%%--------------------------------------------------------------------
%% @doc Decode a JWT into `{Header, Payload, Signature, SigInput}'.
%% `Header' and `Payload' are both decoded JSON as returned by
%% `jsx:decode/1', and `Signature' is the binary signature of the
%% JWT.
%%
%% `SigInput' is the input to the cryptographic signature validation, and is
%% the base64urlencoded JWT header concatenated with `"."' and the
%% base64urlencoded JWT payload, e.g.
%%
%% The JWT is not validated.
%%
%% Returns `{Header, Payload, Signature}' or '{error, invalid_jwt}'.
%% @end
%%--------------------------------------------------------------------
-spec decode_jwt(JWT) -> Result when
      JWT :: jwt(),
      Result :: {Header, Payload, Signature, SigInput} | {error, invalid_jwt},
      Header :: jsx:json_term(), Payload :: jsx:json_term(),
      Signature :: binary(), SigInput :: binary().
decode_jwt(<<JWT/binary>>) ->
    try binary:split(JWT, <<$.>>, [global]) of
        [BHdr, BPayload, _BSig] = L when byte_size(BHdr) >= 3 andalso
                                         byte_size(BPayload) >= 3 andalso
                                         byte_size(_BSig) >= 3 ->
            [Hdr, Payload, Sig] = [base64urldecode(B) || B <- L],
            SigInput = signing_input_hp(BHdr, BPayload),
            {jsx:decode(Hdr), jsx:decode(Payload), Sig, SigInput};
        _ ->
            {error, invalid_jwt}
    catch
        _:_ ->
            {error, invalid_jwt}
    end.


%%--------------------------------------------------------------------
%% @doc
%% Base64urlencode `Bin', without padding.
%% @end
%%--------------------------------------------------------------------
-spec base64urlencode(Bin) -> Result when
      Bin :: binary(), Result :: base64_urlencoded().
base64urlencode(<<>>) ->
    <<>>;
base64urlencode(<<Bin/binary>>) ->
    << << case Byte of $+ -> $-; $/ -> $_; _ -> Byte end >>
       || <<Byte>> <= base64:encode(Bin), Byte =/= $= >>.

%%--------------------------------------------------------------------
%% @doc
%% Base64urldecode `Bin', which may or may not have padding.
%% @end
%%--------------------------------------------------------------------
-spec base64urldecode(Bin) -> Result when
      Bin :: base64_urlencoded(), Result :: binary().
base64urldecode(<<>>) ->
    <<>>;
base64urldecode(<<Bin/binary>>) ->
    base64:decode(<< << case Byte of $- -> $+; $_ -> $/; _ -> Byte end >>
                     || <<Byte>> <= pad(Bin) >>).

%%--------------------------------------------------------------------
%% @doc
%% Return the named elliptic curve tuple for `secp256r1'.
%% @end
%%--------------------------------------------------------------------
-spec named_curve() -> {'namedCurve', OID :: tuple()}.
named_curve() ->
    {namedCurve, 'OTP-PUB-KEY':secp256r1()}.

%%%====================================================================
%%% Internal
%%%====================================================================
%%--------------------------------------------------------------------
-spec signing_input(Context) -> Result when
      Context :: apns_jwt_ctx(), Result :: jws_signing_input().
signing_input(#apns_jwt_ctx{enc_hdr=EncHdr, iss=Iss}) ->
    signing_input_hi(EncHdr, Iss).

-compile({inline, [signing_input/1]}).

%%--------------------------------------------------------------------
-spec signing_input_hi(EncHdr, Iss) -> Result when
      EncHdr :: base64_urlencoded(), Iss :: bstring(),
      Result :: jws_signing_input().
signing_input_hi(<<EncHdr/binary>>, <<Iss/binary>>) ->
    signing_input_hp(EncHdr, base64urlencode(payload(Iss))).

-compile({inline, [signing_input_hi/2]}).
%%--------------------------------------------------------------------
-spec signing_input_hp(EncHdr, EncPayload) -> Result when
      EncHdr :: base64_urlencoded(), EncPayload :: base64_urlencoded(),
      Result :: jws_signing_input().
signing_input_hp(<<EncHdr/binary>>, <<EncPayload/binary>>) ->
    <<EncHdr/binary, $., EncPayload/binary>>.

-compile({inline, [signing_input_hp/2]}).
%%--------------------------------------------------------------------
-spec signing_header(KID) -> Result when
      KID :: kid(), Result :: base64_urlencoded().
signing_header(KID) when is_binary(KID) ->
    base64urlencode(header(KID)).

%%--------------------------------------------------------------------
-spec signature(SigningInput, SigningKey) -> Result when
      SigningInput :: jws_signing_input(), SigningKey :: signing_key(),
      Result :: jws_signature().
signature(SigningInput, SigningKey) when is_binary(SigningInput),
                                         is_binary(SigningKey) ->
    signature(SigningInput, get_private_key(SigningKey));
signature(SigningInput, #'ECPrivateKey'{}=Key) when is_binary(SigningInput) ->
    base64urlencode(bsignature(SigningInput, Key)).

%%--------------------------------------------------------------------
%% @private
-spec pad(B64) -> PaddedB64 when
      B64 :: bstring(), PaddedB64 :: bstring().
pad(<<>>)           -> <<>>;
pad(<<B0>>)         -> <<B0, $=, $=, $=>>;
pad(<<B0, B1>>)     -> <<B0, B1, $=, $=>>;
pad(<<B0, B1, B2>>) -> <<B0, B1, B2, $=>>;
pad(<<B64/binary>>) ->
    case byte_size(B64) rem 4 of
        0 -> B64;
        1 -> erlang:error(badarg);
        N -> <<B64/binary, (pad_eq(4 - N))/binary>>
    end.

%%--------------------------------------------------------------------
%% @private
pad_eq(1) -> <<"=">>;
pad_eq(2) -> <<"==">>.
-compile({inline, [pad_eq/1]}).

%%--------------------------------------------------------------------
%% @equiv header(KeyId, <<"ES256">>)
-spec header(KeyId) -> Result when
      KeyId :: kid(), Result :: jose_header().
header(KeyId) when is_binary(KeyId) ->
    header(KeyId, ?JWT_ALG).

%%--------------------------------------------------------------------
%% @doc Make a JOSE Header according to RFC 7515.
-spec header(KeyId, Alg) -> Result when
      KeyId :: kid(), Alg :: alg(), Result :: jose_header().
header(KeyId, Alg) when is_binary(KeyId), is_binary(Alg) ->
    jsx:encode([{alg, Alg}, {typ, ?JWT_TYP}, {kid, KeyId}]).

%%--------------------------------------------------------------------
%% @doc Make a JWS Payload according to RFC 7515, suitable for APNS,
%% using current erlang system time.
%% @end
%%-------------------------------------------------------------------
-spec payload(Iss) -> Result when
      Iss :: iss(), Result :: jws_payload().
payload(Iss) when is_binary(Iss) ->
    payload(Iss, erlang:system_time(seconds)).

%%--------------------------------------------------------------------
%% @doc Make a JWS Payload according to RFC 7515, suitable for APNS.
-spec payload(Iss, Iat) -> Result when
      Iss :: iss(), Iat :: iat(), Result :: jws_payload().
payload(Iss, Iat) when is_binary(Iss), is_integer(Iat) ->
    jsx:encode([{iss, Iss}, {iat, Iat}]).

%%--------------------------------------------------------------------
%% @private
-compile({inline, [ctx_to_internal/1]}).
-spec ctx_to_internal(Context) -> InternalContext when
      Context :: binary(), InternalContext :: apns_jwt_ctx().
ctx_to_internal(<<Context/binary>>) ->
    #apns_jwt_ctx{} = binary_to_term(Context).

%%--------------------------------------------------------------------
%% @private
-compile({inline, [internal_to_ctx/1]}).
-spec internal_to_ctx(Internal) -> External when
      Internal :: apns_jwt_ctx(), External :: context().
internal_to_ctx(#apns_jwt_ctx{} = Internal) ->
    term_to_binary(Internal).

%%--------------------------------------------------------------------
%% @private
make_internal(KID, Issuer, #'ECPrivateKey'{}=SigningKey) ->
    #apns_jwt_ctx{kid = KID,
                  iss = Issuer,
                  key = SigningKey,
                  enc_hdr = signing_header(KID)};
make_internal(KID, Issuer, <<SigningKeyPem/binary>>) ->
    make_internal(KID, Issuer, get_private_key(SigningKeyPem)).

%%--------------------------------------------------------------------
%% @private
%% @doc Signing is tricky. The signature
%% created by public_key:sign/3 and crypto:sign/3 is in DER-encoded
%% format, which is NOT what APNS wants, which is the raw 64-byte
%% format. The DER-encoded format is 71 bytes long. We have to DER-decode
%% the signature value to get what we want.
%%
%% This can be done (found after much digging) using
%% 'OTP-PUB-KEY':decode('ECDSA-Sig-Value', binary()), which returns a
%% #'ECDSA-Sig-Value'{r, s} record. r and s are both large integers.
%% Encode r and s into a 64-byte binary, consisting of r and s each encoded as
%% big-endian integers, and use that as the signature.
%% @end
%%--------------------------------------------------------------------
-compile({inline, [bsignature/2]}).
bsignature(SigningInput, #'ECPrivateKey'{}=Key) when is_binary(SigningInput) ->
    Sig = public_key:sign(SigningInput, ?DIGEST_TYPE, Key),
    maybe_der_decode_sig(Sig).

%%--------------------------------------------------------------------
%% @private
-compile({inline, [verify_signature/3]}).
verify_signature(Signature, SigningInput, Context) ->
    Sig = maybe_der_encode_sig(Signature),
    public_key:verify(SigningInput, ?DIGEST_TYPE, Sig, public_key(Context)).

%%--------------------------------------------------------------------
%% The reason these verifications may be done without checking against the
%% actual values of `kid' and `iss' in the context, is so they can be called to
%% do a basic verification of the JWT (all required keys present, keys are in
%% expected format, JWT is unexpired) without having a context.  Basically, a
%% partial verification.
%%--------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @private
%% @doc Do a partial verification of the header.
verify_jwt_hdr(Hdr) ->
    verify_jwt_hdr(Hdr, undefined).

%%--------------------------------------------------------------------
%% @private
%% @doc Do a full verification of the header unless Ctx =:= undefined.
verify_jwt_hdr(Hdr, Ctx) ->
    verify_jwt(fun verify_jwt_hdr_item/2, [<<"alg">>, <<"kid">>], Hdr, Ctx).

%%--------------------------------------------------------------------
%% @private
%% @doc Do a partial verification of the payload.
verify_jwt_payload(Payload) ->
    verify_jwt_payload(Payload, undefined).

%%--------------------------------------------------------------------
%% @private
%% @doc Do a full verification of the payload unless Ctx =:= undefined.
verify_jwt_payload(Payload, Ctx) ->
    verify_jwt(fun verify_jwt_payload_item/2, [<<"iss">>, <<"iat">>],
               Payload, Ctx).

%%--------------------------------------------------------------------
%% @private
verify_jwt(VerifyFun, ReqKeys, Props, Ctx) when is_function(VerifyFun, 2),
                                                is_list(ReqKeys),
                                                is_list(Props) ->
    RKBIs = lists:foldl(fun({K, _V}=Item, {RKeys0, BadItems0}) ->
                                     RKeys = lists:delete(K, RKeys0),
                                     BadItems = case VerifyFun(Item, Ctx) of
                                                   true -> BadItems0;
                                                   false -> [Item | BadItems0]
                                               end,
                                     {RKeys, BadItems}
                             end, {ReqKeys, []}, Props),
    canonicalize_error(RKBIs).

%%-------------------------------------------------------------------
%% @private
combine_errors(Errs) when is_list(Errs) ->
    Err = lists:foldl(fun({error, {missing_keys, Ks, bad_items, BIs}},
                          {Ks0, BIs0}) ->
                              {Ks ++ Ks0, BIs ++ BIs0};
                         (_, Acc) ->
                              Acc
                      end, {[], []}, Errs),
    canonicalize_error(Err).

%%--------------------------------------------------------------------
%% @private
canonicalize_error({[], []}) ->
    ok;
canonicalize_error({Ks, Bs}) when is_list(Ks), is_list(Bs) ->
    {error, {missing_keys, Ks, bad_items, Bs}}.

%%--------------------------------------------------------------------
%% @private
-spec verify_jwt_hdr_item(Item, Context) -> boolean() when
      Item :: {Key, Value}, Context :: input_context(),
      Key :: binary(), Value :: any().
verify_jwt_hdr_item({<<"alg">>, Alg}, _Ctx) ->
    Alg =:= ?JWT_ALG;
verify_jwt_hdr_item({<<"kid">>, Kid}, undefined) ->
    is_binary(Kid) andalso byte_size(Kid) > 0;
verify_jwt_hdr_item({<<"kid">>, Kid}, Ctx) ->
    Kid =:= kid(Ctx);
verify_jwt_hdr_item({<<"typ">>, Typ}, _Ctx) ->
    Typ =:= ?JWT_TYP;
verify_jwt_hdr_item(_Item, _Ctx) ->
    true. % Allow any other items

%%--------------------------------------------------------------------
%% @private
-spec verify_jwt_payload_item(Item, Context) -> boolean() when
      Item :: {Key, Value}, Context :: input_context(),
      Key :: binary(), Value :: any().
verify_jwt_payload_item({<<"iss">>, Iss}, undefined) ->
    is_binary(Iss) andalso byte_size(Iss) > 0;
verify_jwt_payload_item({<<"iss">>, Iss}, Ctx) ->
    Iss =:= iss(Ctx);
verify_jwt_payload_item({<<"iat">>, Iat}, _Ctx) ->
    is_integer(Iat) andalso
    erlang:system_time(seconds) - Iat < ?MAX_IAT_AGE_SECS;
verify_jwt_payload_item(_, _Ctx) ->
    true.

%%--------------------------------------------------------------------
%% @private
generate_private_key_info(Curve, #'ECPrivateKey'{}=ECPrivateKey) ->
    {ok, PrivKeyOctets} = 'OTP-PUB-KEY':encode('ECPrivateKey', ECPrivateKey),
    {ok, EcpkOctets} = 'OTP-PUB-KEY':encode('EcpkParameters', Curve),
    AlgOID = 'OTP-PUB-KEY':'id-ecPublicKey'(),
    ECParameters = {asn1_OPENTYPE, EcpkOctets},
    Alg = #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm=AlgOID,
                                                parameters=ECParameters},
    #'PrivateKeyInfo'{version=v1,
                      privateKeyAlgorithm=Alg,
                      privateKey=PrivKeyOctets}.


%%--------------------------------------------------------------------
%% @private
maybe_der_encode_sig(<<R:32/big-integer-unit:8, S:32/big-integer-unit:8>>) ->
    ECDSASigValue = #'ECDSA-Sig-Value'{r=R, s=S},
    {ok, DEREncSig} = 'OTP-PUB-KEY':encode('ECDSA-Sig-Value', ECDSASigValue),
    DEREncSig;
maybe_der_encode_sig(<<Sig/binary>>) ->
    Sig.

%%--------------------------------------------------------------------
%% @private
maybe_der_decode_sig(<<Sig/binary>>) ->
    try 'OTP-PUB-KEY':decode('ECDSA-Sig-Value', Sig) of
        {ok, ECDSASigValue} ->
            #'ECDSA-Sig-Value'{r=R, s=S} = ECDSASigValue,
            <<R:32/big-integer-unit:8, S:32/big-integer-unit:8>>;
        _ ->
            Sig
    catch
        _:_ ->
            Sig
    end.

