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
%%% @copyright 2015 Silent Circle LLC
%%% @doc APNS certificate utilities.  This module provides functions to decode
%%% and validate APNS PEM and DER format certificates, given a Bundle Seed ID
%%% and the Bundle ID.  See
%%% [https://developer.apple.com/ios/manage/bundles/index.action] (iOS
%%% developer and iOS portal access required).
%%% @end
%%%-------------------------------------------------------------------

-module(apns_cert).

-export([
          validate/3
        , pem_decode_certs/1
        , der_decode_cert/1
        , get_cert_info/1
    ]).


-include_lib("public_key/include/public_key.hrl").

-ifndef('id-userid').
-define('id-userid', {0,9,2342,19200300,100,1,1}).
-endif.

%% Last submatch must be either BundleSeedID:BundleID or just BundleID
-define(APP_ID_RE,
    "^Apple\\s(Production|Development)(\\sIOS)?\\sPush\\sServices:\\s(.*)$").

-define(APP_ID_RE_VOIP, "VoIP\\sServices:\\s(.*)").

-define(WWDR_NAME,
    <<"Apple Worldwide Developer Relations Certification Authority">>).

-type bin_or_string() :: binary() | string().
-type special_string() ::
    {teletexString, bin_or_string()} | {printableString, bin_or_string()} |
    {universalString, bin_or_string()} | {utf8String, bin_or_string()} |
    {bmpString, bin_or_string()}.

-record(cert_info, {
        issuer_cn = <<>> :: binary(),
        is_production = false :: boolean(),
        bundle_id = <<>> :: binary(),
        bundle_seed_id = <<>> :: binary()
    }).

%% @doc Validate that the `BundleSeedID' and `BundleID' correspond to the
%% certificate data `CertData'. `CertData' may be either PEM-encoded or
%% DER-encoded. If PEM-encoded, only one certificate is permitted in
%% the data.
%% === Cert Data ===
%% Depending on whether or not the certificate is PEM or DER
%% encoded, you could load it as follows:
%% ```
%% {ok, PemData} = file:read_file("cert.pem").
%% {ok, DerData} = file:read_file("aps_developer.cer").
%% '''
%% === Bundle Seed ID ===
%%
%% The bundle seed ID will be either in the form `^.{10}:.{10}$',
%% such as `ABCDE12345:FGHIJ67890', or
%% a bundle ID string such as `com.example.MyApp'. The caller is
%% expected to supply the right bundle seed ID format or the validation
%% will fail.
%%
%% The Issuer CN is expected to be
%% `Apple Worldwide Developer Relations Certification Authority'
%% or the validation will fail.
%%
%% @end
-spec validate(CertData::binary(), BundleSeedID::binary(), BundleID::binary()) ->
    ok | {ErrorClass::atom(), Reason::term()}.
validate(<<CertData/binary>>, <<BundleSeedID/binary>>, <<BundleID/binary>>) ->
    IssuerCN = ?WWDR_NAME,
    case get_cert_info(decode_cert(CertData)) of
        #cert_info{bundle_seed_id = BundleSeedID,
                   bundle_id = BundleID,
                   issuer_cn = IssuerCN} ->
            ok;
        #cert_info{} = CertInfo ->
            {error, {mismatched_cert, [
                        {expected, [BundleSeedID, BundleID, IssuerCN]},
                        {actual, CertInfo}]}}
    end.

decode_cert(CertData) ->
    {PemOk, OTPCertRec} = try
        [R] = pem_decode_certs(CertData),
        {true, #'OTPCertificate'{} = R}
    catch _:_ ->
        {false, undefined}
    end,

    case PemOk of
        true ->
            OTPCertRec;
        false ->
            der_decode_cert(CertData)
    end.

%%--------------------------------------------------------------------
%% @doc Decode PEM binary into a list of #'OTPCertificate'{} records.
%% @end
%%--------------------------------------------------------------------
-spec pem_decode_certs(PemData::binary()) ->
    [#'OTPCertificate'{}] | {error, Reason::term()}.
pem_decode_certs(<<PemData/binary>>) ->
    [
        der_decode_cert(DerCert) ||
        {_, DerCert, _} <- public_key:pem_decode(PemData)
    ].

%%--------------------------------------------------------------------
%% @doc Decode DER binary into an #'OTPCertificate'{} record.
%% @end
%%--------------------------------------------------------------------
-spec der_decode_cert(DerData::binary()) ->
    #'OTPCertificate'{} | {error, Reason::term()}.
der_decode_cert(<<DerData/binary>>) ->
    try
        #'OTPCertificate'{} = public_key:pkix_decode_cert(DerData, otp)
    catch
        Class:Reason ->
            Trace = erlang:get_stacktrace(),
            erlang:raise(Class, {invalid_cert, Reason}, Trace)
    end.

%%--------------------------------------------------------------------
%% @doc Extract interesting APNS-related info from cert.
%% @end
%%--------------------------------------------------------------------
-spec get_cert_info(OTPCert::#'OTPCertificate'{}) -> #cert_info{}.
get_cert_info(#'OTPCertificate'{tbsCertificate = R}) ->
    Decode = fun(Val) ->
        {utf8String, Decoded} = maybe_decode_val('DirectoryString', Val),
        Decoded
    end,
    %% Subject
    {rdnSequence, SubjectRdnSeq} = R#'OTPTBSCertificate'.subject,
    [SubjectUID] = select_attr(?'id-userid', SubjectRdnSeq, Decode),
    [SubjectCN] = select_attr(?'id-at-commonName', SubjectRdnSeq, Decode),

    %% Issuer
    {rdnSequence, IssuerRdnSeq} = R#'OTPTBSCertificate'.issuer,
    [IssuerCN] = select_attr(?'id-at-commonName', IssuerRdnSeq, Decode),

    {ok, {IsProd, BundleInfo}} = extract_bundle_info(SubjectCN),

    #cert_info{
        issuer_cn = IssuerCN,
        bundle_id = SubjectUID,
        bundle_seed_id = BundleInfo,
        is_production = IsProd
    }.

%%--------------------------------------------------------------------
%% @doc Extract the bundle seed info and production/development status
%% from the Subject CommonName field.
%% @end
%%--------------------------------------------------------------------
-spec extract_bundle_info(CN::binary()) ->
    {ok, {IsProd::boolean(), BundleInfo::binary()}} | {error, Reason::term()}.

extract_bundle_info(CN) ->
    {ok, Str} = unicode_to_list(CN),
    case re:run(Str, ?APP_ID_RE, [{capture, all_but_first, binary}]) of
        {match, [ProdOrDev, _MaybeIOS, BundleInfo]} ->
            {ok, {is_production(ProdOrDev), BundleInfo}};
        nomatch ->
            case re:run(Str, ?APP_ID_RE_VOIP, [{capture, all_but_first, binary}]) of
                {match, [BundleInfo]} ->
                    {ok, {true, BundleInfo}}; % Assume prod for now
                nomatch ->
                    {error, {not_an_apns_cert, Str}}
            end
    end.

is_production(<<"Production">>) -> true;
is_production(<<"Development">>) -> false.

unicode_to_list(Unicode) ->
    case unicode:characters_to_list(Unicode) of
        L when is_list(L) ->
            {ok, L};
        Error ->
            Error
    end.

-spec maybe_decode_val(Type::atom(), term()) -> special_string().
maybe_decode_val(Type, <<_Tag, _Length, _Value/binary>> = Tlv) ->
    {ok, SpecialString} = 'OTP-PUB-KEY':decode(Type, Tlv),
    maybe_decode_val(undefined, SpecialString);
maybe_decode_val(_Type, {SpecialStringType, V}) ->
    {SpecialStringType, iolist_to_binary(V)}. % Already decoded

%%--------------------------------------------------------------------
%% @doc Get attribute value from list.
%% Note that `AttrType' is an OID [http://oid-info.com/#oid] in `tuple' form.
%% Had to define id-userid attribute type because it was
%% not included in public_key.hrl.
%% See [http://oid-info.com/get/0.9.2342.19200300.100.1.1]
%% @end
%%--------------------------------------------------------------------
-spec select_attr(
    AttrType::tuple(),
    AttrVals::[[#'AttributeTypeAndValue'{}]],
    Decode::fun((special_string() | binary()) -> binary())
) -> [binary()].

select_attr(AttrType, AttrVals, Decode) when is_function(Decode, 1) ->
    [Decode(AttrVal) ||
        [#'AttributeTypeAndValue'{type = T, value = AttrVal}] <- AttrVals,
        T =:= AttrType].

