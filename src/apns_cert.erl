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
%%% @copyright 2015-2016 Silent Circle
%%% @doc APNS certificate utilities.
%%% This module provides functions to decode and
%%% validate APNS PEM and DER format certificates, given a Bundle Seed ID
%%% and the Bundle ID.
%%% See [https://developer.apple.com] for more information.
%%% @end
%%%-------------------------------------------------------------------
-module(apns_cert).

%%-------------------------------------------------------------------
%% Exports
%%-------------------------------------------------------------------
-export([
           decode_cert/1
         , der_decode_cert/1
         , get_cert_info/1
         , get_cert_info_map/1
         , pem_decode_certs/1
         , validate/3
        ]).

%%-------------------------------------------------------------------
%% Includes
%%-------------------------------------------------------------------
-include_lib("public_key/include/public_key.hrl").
-include("ApnsCerts.hrl").

%%-------------------------------------------------------------------
%% Defines
%%-------------------------------------------------------------------
-ifndef('id-userid').
-define('id-userid', {0,9,2342,19200300,100,1,1}).
-endif.

-define(ASN1_NULL_BIN, <<5, 0>>).

-define(APP_ID_RE, "^("
                   "Apple\\s+Push\\s+Services|"
                   "Apple\\s+Production(\\s+IOS)?\\s+Push\\s+Services|"
                   "Apple\\s+Development(\\s+IOS)?\\s+Push\\s+Services|"
                   "VoIP\\s+Services|"
                   "Website\\s+Push\\s+ID|"
                   "Pass\\s+Type\\s+ID|"
                   "WatchKit\s+Services"
                   ")" % This group is not captured because all_names is used
                   ":\\s+(?<app_id>.*)$"
       ).

-define(WWDR_NAME,
    <<"Apple Worldwide Developer Relations Certification Authority">>).

-define(is_digit(X), ($0 =< X andalso X =< $9)).

-define(bit7_clear(N), (N band 16#80 =:= 0)).
-define(bit7_set(N), (not ?bit7_clear(N))).

%%-------------------------------------------------------------------
%% Types
%%-------------------------------------------------------------------
-type bin_or_string() :: binary() | string().
-type special_string() ::
    {teletexString, bin_or_string()} | {printableString, bin_or_string()} |
    {universalString, bin_or_string()} | {utf8String, bin_or_string()} |
    {bmpString, bin_or_string()}.
-type cert_info() :: term().

%%%====================================================================
%%% API
%%%====================================================================

%%--------------------------------------------------------------------
%% @doc Decode binary certificate data into an `` #'OTPCertificate'{} ''
%% record.
%% @end
%%--------------------------------------------------------------------
-spec decode_cert(CertData) -> Result when
      CertData :: binary(),
      Result :: #'OTPCertificate'{} | {error, Reason::term()}.
decode_cert(<<CertData/binary>>) ->
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
-spec get_cert_info(OTPCert) -> CertInfo when
      OTPCert :: #'OTPCertificate'{}, CertInfo :: cert_info().
get_cert_info(#'OTPCertificate'{} = OTPCert) ->
    #{subject_uid   := SubjectUID,
      subject_cn    := SubjectCN,
      issuer_cn     := IssuerCN,
      is_production := IsProd} = get_cert_info_map(OTPCert),

    {ok, BundleInfo} = extract_bundle_info(SubjectCN),

    apns_recs:'#new-cert_info'([
                                {issuer_cn, IssuerCN},
                                {bundle_id, SubjectUID},
                                {bundle_seed_id, BundleInfo},
                                {is_production, IsProd =:= true}
                               ]
                              ).

%%--------------------------------------------------------------------
%% @doc Extract more interesting APNS-related info from cert and
%% return in a map.
%% @end
%%--------------------------------------------------------------------
-spec get_cert_info_map(OTPCert) -> CertInfo when
      OTPCert :: #'OTPCertificate'{}, CertInfo :: map().
get_cert_info_map(#'OTPCertificate'{tbsCertificate = R}) ->
    %% Serial
    SerialNumber = R#'OTPTBSCertificate'.serialNumber,

    %% Subject
    SubjAttrs = [
                 {?'id-at-commonName',              subject_cn},
                 {?'id-userid',                     subject_uid},
                 {?'id-at-organizationName',        subject_o},
                 {?'id-at-organizationalUnitName',  subject_ou},
                 {?'id-at-localityName',            subject_l},
                 {?'id-at-stateOrProvinceName',     subject_st},
                 {?'id-at-countryName',             subject_c}
                ],
    {rdnSequence, SubjectRdnSeq} = R#'OTPTBSCertificate'.subject,

    %% Issuer
    IssuerAttrs = [
                   {?'id-at-commonName',              issuer_cn},
                   {?'id-at-organizationName',        issuer_o},
                   {?'id-at-organizationalUnitName',  issuer_ou},
                   {?'id-at-stateOrProvinceName',     issuer_st},
                   {?'id-at-localityName',            issuer_l},
                   {?'id-at-countryName',             issuer_c}
                  ],
    {rdnSequence, IssuerRdnSeq} = R#'OTPTBSCertificate'.issuer,

    %% Extensions
    ExtAttrs = [
                {?'id-apns-development', is_development},
                {?'id-apns-production',  is_production},
                {?'id-apns-bundle-id',   bundle_id},
                {?'id-apns-bundle-info', bundle_info},
                {?'id-apns-topics',      topics}
               ],
    Extensions = R#'OTPTBSCertificate'.extensions,

    Validity = R#'OTPTBSCertificate'.validity,
    NotBefore = format_time(Validity#'Validity'.notBefore),
    NotAfter = format_time(Validity#'Validity'.notAfter),

    Expired = cert_is_expired(parse_time(Validity#'Validity'.notAfter)),
    ExpMsg = case Expired of
                 true ->
                     "*** THIS CERTIFICATE IS EXPIRED! ***";
                 false ->
                     "Unexpired"
             end,

    maps:from_list(
      [
       {expiry_status, ExpMsg},
       {serial_number, SerialNumber},
       {not_before, NotBefore},
       {not_after, NotAfter}
      ] ++
      extract_attrs(SubjAttrs, SubjectRdnSeq) ++
      extract_attrs(IssuerAttrs, IssuerRdnSeq) ++
      extract_exts(ExtAttrs, Extensions)
     ).


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
%%--------------------------------------------------------------------
-spec validate(CertData::binary(), BundleSeedID::binary(), BundleID::binary()) ->
    ok | {ErrorClass::atom(), Reason::term()}.
validate(<<CertData/binary>>, <<BundleSeedID/binary>>, <<BundleID/binary>>) ->
    IssuerCN = ?WWDR_NAME,
    CertInfo = get_cert_info(decode_cert(CertData)),
    true = apns_recs:'#is_record-'(cert_info, CertInfo),
    case {get_bundle_seed_id(CertInfo), get_bundle_id(CertInfo),
          get_issuer_cn(CertInfo)} of
        {BundleSeedID, BundleID, IssuerCN} ->
            ok;
        _ ->
            {error, {mismatched_cert,
                     [{expected, [BundleSeedID, BundleID, IssuerCN]},
                      {actual, CertInfo}]
                    }
            }
    end.

%%%====================================================================
%%% Internal functions
%%%====================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc Extract bundle info and production/development status.
%% @end
%%--------------------------------------------------------------------
-spec extract_bundle_info(CN) -> Result when
      CN :: binary(), Result :: {ok, BundleInfo} | {error, Reason},
      BundleInfo :: binary(), Reason :: term().
extract_bundle_info(CN) ->
    {ok, Str} = unicode_to_list(CN),
    {ok, RE} = re:compile(?APP_ID_RE),
    {namelist, [_|_] = NL} = re:inspect(RE, namelist),
    case re:run(Str, RE, [{capture, all_names, binary}]) of
        {match, Matches} ->
            MatchProps = lists:zip(NL, Matches),
            BundleInfo = proplists:get_value(<<"app_id">>, MatchProps),
            {ok, BundleInfo};
        nomatch ->
            {error, {not_an_apns_cert, Str}}
    end.

%%--------------------------------------------------------------------
%% @private
unicode_to_list(Unicode) ->
    case unicode:characters_to_list(Unicode) of
        L when is_list(L) ->
            {ok, L};
        Error ->
            Error
    end.

%%--------------------------------------------------------------------
%% @private
-spec maybe_decode_val(Type, Val) -> Result when
      Type :: atom(), Val :: term(), Result :: special_string() | undefined.
maybe_decode_val(Type, <<_Tag, _Length, _Value/binary>> = Tlv) ->
    {ok, SpecialString} = 'OTP-PUB-KEY':decode(Type, Tlv),
    maybe_decode_val(undefined, SpecialString);
maybe_decode_val(_Type, {SpecialStringType, V}) ->
    {SpecialStringType, iolist_to_binary(V)}; % Already decoded
maybe_decode_val(_Type, S) when is_list(S) ->
    S;
maybe_decode_val(_Type, _Unknown) ->
    undefined.

-compile({inline, [{get_bundle_seed_id, 1},
                   {get_bundle_id, 1},
                   {get_issuer_cn, 1}]}).

%%--------------------------------------------------------------------
%% @private
get_bundle_seed_id(CertInfo) ->
    apns_recs:'#get-cert_info'(bundle_seed_id, CertInfo).

%%--------------------------------------------------------------------
%% @private
get_bundle_id(CertInfo) ->
    apns_recs:'#get-cert_info'(bundle_id, CertInfo).

%%--------------------------------------------------------------------
%% @private
get_issuer_cn(CertInfo) ->
    apns_recs:'#get-cert_info'(issuer_cn, CertInfo).

%%--------------------------------------------------------------------
%% @private
now_to_gregorian_seconds(Now) ->
    calendar:datetime_to_gregorian_seconds(calendar:now_to_datetime(Now)).

%%--------------------------------------------------------------------
%% @private
cert_is_expired(DateTime) ->
    GSNow = now_to_gregorian_seconds(os:timestamp()),
    GSCert = calendar:datetime_to_gregorian_seconds(DateTime),
    GSNow >= GSCert.

%%--------------------------------------------------------------------
%% @private
-spec extract_attrs(Attrs, AttrVals) -> Result when
      Attrs :: [{Id, Name}], AttrVals :: [[#'AttributeTypeAndValue'{}]],
      Id :: tuple(), Name :: atom(),
      Result :: [{atom(), binary() | undefined}].
extract_attrs(Attrs, AttrVals) ->
    [{Name, select_attr(Id, AttrVals)} || {Id, Name} <- Attrs].

%%--------------------------------------------------------------------
%% @private
-spec extract_exts(Exts, ExtVals) -> Result when
      Exts :: [{Id, Name}], Id :: tuple(), Name :: atom(),
      ExtVals :: asn1_NOVALUE | [[#'AttributeTypeAndValue'{}]],
      Result :: [{atom(), binary() | undefined}].
extract_exts(_Exts, asn1_NOVALUE) ->
    [];
extract_exts(Exts, ExtVals) ->
    [{Name, select_ext(Id, ExtVals)} || {Id, Name} <- Exts].

%%--------------------------------------------------------------------
%% @private
%% @doc Get attribute value from list.
%% Note that `AttrType' is an OID [http://oid-info.com/#oid] in `tuple' form.
%% Had to define id-userid attribute type because it was
%% not included in public_key.hrl.
%% See [http://oid-info.com/get/0.9.2342.19200300.100.1.1]
%% @end
%%--------------------------------------------------------------------
-spec select_attr(AttrType, AttrVals) -> Result when
      AttrType :: tuple(), AttrVals :: [[#'AttributeTypeAndValue'{}]],
      Result :: binary() | undefined.
select_attr(AttrType, AttrVals) ->
    L = [decode_attr(AttrVal) ||
         [#'AttributeTypeAndValue'{type = T, value = AttrVal}] <- AttrVals,
         T =:= AttrType],
    case L of
        [Val|_] -> Val;
        _       -> undefined
    end.

%%--------------------------------------------------------------------
%% @private
-spec select_ext(ExtID, ExtVals) -> Result when
      ExtID :: tuple(), ExtVals :: asn1_NOVALUE | [#'Extension'{}],
      Result :: term() | undefined.
select_ext(_ExtID, asn1_NOVALUE) ->
    undefined;
select_ext(?'id-apns-topics', ExtVals) ->
    maybe_extract_topics(ExtVals);
select_ext(ExtID, ExtVals) ->
    decode_ext(extract_ext(ExtID, ExtVals)).

%%--------------------------------------------------------------------
%% @private
maybe_extract_topics(ExtVals) ->
    case extract_ext(?'id-apns-topics', ExtVals) of
        undefined ->
            undefined;
        EncodedTopics ->
            {ok, Topics} = 'ApnsCerts':decode('ApnsTopics', EncodedTopics),
            rearrange_topics(Topics)
    end.

%%--------------------------------------------------------------------
%% @private
extract_ext(ExtID, ExtVals) ->
    case [E#'Extension'.extnValue
          || #'Extension'{extnID=EID} = E <- ExtVals, EID =:= ExtID] of
        [Val] when is_binary(Val) ->
            Val;
        _ ->
            undefined
    end.

%%--------------------------------------------------------------------
%% @private
decode_attr(Val) ->
   Res = maybe_decode_val('DirectoryString', Val),
   decode_special_string(Res).

%%--------------------------------------------------------------------
%% @private
decode_ext(undefined) ->
    undefined;
decode_ext(?ASN1_NULL_BIN) ->
    true; % ASN.1 NULL value, but this is present, so true is good enough.
decode_ext(Val) ->
    Res = maybe_decode_val('DirectoryString', Val),
    decode_special_string(Res).

%%--------------------------------------------------------------------
%% @private
decode_special_string({T, S}) when T =:= utf8String orelse
                                   T =:= printableString orelse
                                   T =:= teletexString orelse
                                   T =:= universalString orelse
                                   T =:= bmpString ->
    S;
decode_special_string(X) ->
    X.


%%--------------------------------------------------------------------
%% @private
month(1)  -> "Jan";
month(2)  -> "Feb";
month(3)  -> "Mar";
month(4)  -> "Apr";
month(5)  -> "May";
month(6)  -> "Jun";
month(7)  -> "Jul";
month(8)  -> "Aug";
month(9)  -> "Sep";
month(10) -> "Oct";
month(11) -> "Nov";
month(12) -> "Dec".


%%--------------------------------------------------------------------
%% 4.1.2.5.1.  UTCTime
%%
%%    ...
%%
%%    For the purposes of this profile, UTCTime values MUST be expressed in
%%    Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
%%    YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
%%    systems MUST interpret the year field (YY) as follows:
%%
%%       Where YY is greater than or equal to 50, the year SHALL be
%%       interpreted as 19YY; and
%%
%%       Where YY is less than 50, the year SHALL be interpreted as 20YY.
%%--------------------------------------------------------------------

-type asn1_time_type() :: utcTime | generalTime.

%% @private
-spec format_time({asn1_time_type(), string()}) -> string().
format_time({utcTime, [Y1, Y2|_] = UTCTime}) when length(UTCTime) == 13 ->
    format_time({generalTime, utctime_century(Y1, Y2) ++ UTCTime});
format_time({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2,
                           H1, H2, Mn1, Mn2, S1, S2, $Z]}) ->
    Month = month(dd_to_int(M1, M2)),
    Month ++ [$\s, D1, D2, $\s, H1, H2, $:, Mn1, Mn2, $:, S1, S2,
              $\s, Y1, Y2, Y3, Y4] ++ " GMT".

%%--------------------------------------------------------------------
-type digit() :: 16#30 .. 16#39.
-spec utctime_century(digit(), digit()) -> string().
%% @private
utctime_century(Y1, Y2) ->
    case dd_to_int(Y1, Y2) >= 50 of
        true  -> "19";
        false -> "20"
    end.

%%--------------------------------------------------------------------
-spec parse_time({asn1_time_type(), string()}) -> calendar:datetime().
%% @private
parse_time({utcTime, [Y1, Y2|_] = UTCTime}) when length(UTCTime) == 13 ->
    parse_time({generalTime, utctime_century(Y1, Y2) ++ UTCTime});
parse_time({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2,
                          H1, H2, Mn1, Mn2, S1, S2, $Z]}) ->
    Date = {dddd_to_int(Y1, Y2, Y3, Y4), dd_to_int(M1, M2), dd_to_int(D1, D2)},
    Time = {dd_to_int(H1, H2), dd_to_int(Mn1, Mn2), dd_to_int(S1, S2)},
    {Date, Time}.

%%--------------------------------------------------------------------
-compile({inline, [{dddd_to_int, 4},
                   {dd_to_int, 2},
                   {d_to_int, 1}]}).

%% @private
dddd_to_int(A, B, C, D) ->
    d_to_int(A) * 1000 +
    d_to_int(B) * 100 +
    dd_to_int(C, D).

%%--------------------------------------------------------------------
%% @private
dd_to_int($0, B) ->
    d_to_int(B);
dd_to_int(A, B) when ?is_digit(A) andalso ?is_digit(B) ->
    d_to_int(A) * 10 + d_to_int(B).

%%--------------------------------------------------------------------
%% @private
d_to_int(A) when ?is_digit(A) ->
    A - $0.

%%--------------------------------------------------------------------
-spec rearrange_topics(list()) -> list().

rearrange_topics([{name, <<TopicName/binary>>}, {type, TopicType} | T]) ->
    [{TopicName, TopicType#'ApnsTopicType'.name} | rearrange_topics(T)];
rearrange_topics([]) ->
    [].

