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

-export([
          validate/3
        , decode_cert/1
        , pem_decode_certs/1
        , der_decode_cert/1
        , get_cert_info/1
        , get_cert_info_map/1
        , asn1_decode/1
        ]).

-include_lib("public_key/include/public_key.hrl").

%%-------------------------------------------------------------------
%% Defines
%%-------------------------------------------------------------------
-ifndef('id-userid').
-define('id-userid', {0,9,2342,19200300,100,1,1}).
-endif.

-define('id-apns-development', {1,2,840,113635,100,6,3,1}).
-define('id-apns-production',  {1,2,840,113635,100,6,3,2}).
-define('id-apns-bundle-id',   {1,2,840,113635,100,6,3,3}).
-define('id-apns-bundle-info', {1,2,840,113635,100,6,3,4}).
-define('id-apns-topics',      {1,2,840,113635,100,6,3,6}).

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

-type asn1_tag() :: asn1_boolean()
                  | asn1_integer()
                  | asn1_bit_string()
                  | asn1_octet_string()
                  | asn1_null()
                  | asn1_object_identifier()
                  | asn1_utf8_string()
                  | asn1_printable_string()
                  | asn1_teletex_string()
                  | asn1_ia5_string()
                  | asn1_bmp_string().

-type asn1_tag_val() :: {asn1_tag(), binary()}
                      | {asn1_sequence(), [asn1_tag_val()]}.

-type asn1_boolean()           :: 16#01.
-type asn1_integer()           :: 16#02.
-type asn1_bit_string()        :: 16#03.
-type asn1_octet_string()      :: 16#04.
-type asn1_null()              :: 16#05.
-type asn1_object_identifier() :: 16#06.
-type asn1_sequence()          :: 16#10.
-type asn1_utf8_string()       :: 16#0C.
-type asn1_printable_string()  :: 16#13.
-type asn1_teletex_string()    :: 16#14.
-type asn1_ia5_string()        :: 16#16.
-type asn1_bmp_string()        :: 16#1E.

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
            {error, {mismatched_cert, [
                        {expected, [BundleSeedID, BundleID, IssuerCN]},
                        {actual, CertInfo}]}}
    end.

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
unicode_to_list(Unicode) ->
    case unicode:characters_to_list(Unicode) of
        L when is_list(L) ->
            {ok, L};
        Error ->
            Error
    end.

%%--------------------------------------------------------------------
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

%%--------------------------------------------------------------------
%% @doc Get attribute value from list.
%% Note that `AttrType' is an OID [http://oid-info.com/#oid] in `tuple' form.
%% Had to define id-userid attribute type because it was
%% not included in public_key.hrl.
%% See [http://oid-info.com/get/0.9.2342.19200300.100.1.1]
%% @end
%%--------------------------------------------------------------------
-compile({inline, [{get_bundle_seed_id, 1},
                   {get_bundle_id, 1},
                   {get_issuer_cn, 1}]}).

get_bundle_seed_id(CertInfo) ->
    apns_recs:'#get-cert_info'(bundle_seed_id, CertInfo).

%%--------------------------------------------------------------------
get_bundle_id(CertInfo) ->
    apns_recs:'#get-cert_info'(bundle_id, CertInfo).

%%--------------------------------------------------------------------
get_issuer_cn(CertInfo) ->
    apns_recs:'#get-cert_info'(issuer_cn, CertInfo).

%%--------------------------------------------------------------------
now_to_gregorian_seconds(Now) ->
    calendar:datetime_to_gregorian_seconds(calendar:now_to_datetime(Now)).

%%--------------------------------------------------------------------
cert_is_expired(DateTime) ->
    GSNow = now_to_gregorian_seconds(os:timestamp()),
    GSCert = calendar:datetime_to_gregorian_seconds(DateTime),
    GSNow >= GSCert.

%%--------------------------------------------------------------------
-spec extract_attrs(Attrs, AttrVals) -> Result when
      Attrs :: [{Id, Name}], AttrVals :: [[#'AttributeTypeAndValue'{}]],
      Id :: tuple(), Name :: atom(),
      Result :: [{atom(), binary() | undefined}].
extract_attrs(Attrs, AttrVals) ->
    [{Name, select_attr(Id, AttrVals)} || {Id, Name} <- Attrs].

%%--------------------------------------------------------------------
-spec extract_exts(Exts, ExtVals) -> Result when
      Exts :: [{Id, Name}], Id :: tuple(), Name :: atom(),
      ExtVals :: asn1_NOVALUE | [[#'AttributeTypeAndValue'{}]],
      Result :: [{atom(), binary() | undefined}].
extract_exts(_Exts, asn1_NOVALUE) ->
    [];
extract_exts(Exts, ExtVals) ->
    [{Name, select_ext(Id, ExtVals)} || {Id, Name} <- Exts].

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
maybe_extract_topics(ExtVals) ->
    case extract_ext(?'id-apns-topics', ExtVals) of
        undefined ->
            undefined;
        EncodedTopics ->
            {Topics, _} = asn1_decode(EncodedTopics),
            rearrange_topics(Topics)
    end.

%%--------------------------------------------------------------------
extract_ext(ExtID, ExtVals) ->
    case [E#'Extension'.extnValue
          || #'Extension'{} = E <- ExtVals, E#'Extension'.extnID =:= ExtID] of
        [Val|_] ->
            Val;
        _ ->
            undefined
    end.

%%--------------------------------------------------------------------
decode_attr(Val) ->
   Res = maybe_decode_val('DirectoryString', Val),
   decode_special_string(Res).

%%--------------------------------------------------------------------
decode_ext(undefined) ->
    undefined;
decode_ext(?ASN1_NULL_BIN) ->
    true; % ASN.1 NULL value, but this is present, so true is good enough.
decode_ext(Val) ->
    Res = maybe_decode_val('DirectoryString', Val),
    decode_special_string(Res).

%%--------------------------------------------------------------------
decode_special_string({T, S}) when T =:= utf8String orelse
                                   T =:= printableString orelse
                                   T =:= teletexString orelse
                                   T =:= universalString orelse
                                   T =:= bmpString ->
    S;
decode_special_string(X) ->
    X.


%%--------------------------------------------------------------------
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

-spec format_time({asn1_time_type(), string()}) -> string().
format_time({utcTime, [Y1, Y2|_] = UTCTime}) when length(UTCTime) == 13 ->
    format_time({generalTime, utctime_century(Y1, Y2) ++ UTCTime});
format_time({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2,
                           H1, H2, Mn1, Mn2, S1, S2, $Z]}) ->
    Month = month(dd_to_int(M1, M2)),
    Month ++ [$\s, D1, D2, $\s, H1, H2, $:, Mn1, Mn2, $:, S1, S2,
              $\s, Y1, Y2, Y3, Y4] ++ " GMT".

-type digit() :: 16#30 .. 16#39.
-spec utctime_century(digit(), digit()) -> string().
utctime_century(Y1, Y2) ->
    case dd_to_int(Y1, Y2) >= 50 of
        true  -> "19";
        false -> "20"
    end.

-spec parse_time({asn1_time_type(), string()}) -> calendar:datetime().
parse_time({utcTime, [Y1, Y2|_] = UTCTime}) when length(UTCTime) == 13 ->
    parse_time({generalTime, utctime_century(Y1, Y2) ++ UTCTime});
parse_time({generalTime, [Y1, Y2, Y3, Y4, M1, M2, D1, D2,
                          H1, H2, Mn1, Mn2, S1, S2, $Z]}) ->
    Date = {dddd_to_int(Y1, Y2, Y3, Y4), dd_to_int(M1, M2), dd_to_int(D1, D2)},
    Time = {dd_to_int(H1, H2), dd_to_int(Mn1, Mn2), dd_to_int(S1, S2)},
    {Date, Time}.

%%--------------------------------------------------------------------
dddd_to_int(A, B, C, D) ->
    d_to_int(A) * 1000 +
    d_to_int(B) * 100 +
    dd_to_int(C, D).

%%--------------------------------------------------------------------
dd_to_int($0, B) ->
    d_to_int(B);
dd_to_int(A, B) when ?is_digit(A) andalso ?is_digit(B) ->
    d_to_int(A) * 10 + d_to_int(B).

%%--------------------------------------------------------------------
d_to_int(A) when ?is_digit(A) ->
    A - $0.

-compile({inline, [{dddd_to_int, 4},
                   {dd_to_int, 2},
                   {d_to_int, 1}]}).

%%%====================================================================
%%% ASN.1 DER decoding (subset just to handle Apple X509 topic extension)
%%%====================================================================
-define(asn1_indefinite_form(N), ((N) band 2#10000000 == 2#10000000)).
-define(asn1_short_form(N), ((N) band 2#10000000 == 0)).
-define(asn1_long_form(N), ((N) band 2#10000000 /= 0)).

%%% For more info, see https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
%%--------------------------------------------------------------------
%% Sample return from asn1tr_nif:decode_ber_tlv/1:
%%
%% ExtnValue = <<48,112,12,19,99,111,109,46,101,120,97,109,112,108,101,
%%               46,70,97,107,101,65,112,112,48,5,12,3,97,112,112,12,24,
%%               99,111,109,46,101,120,97,109,112,108,101,46,70,97,107,
%%               101,65,112,112,46,118,111,105,112,48,6,12,4,118,111,105,
%%               112,12,32,99,111,109,46,101,120,97,109,112,108,101,46,
%%               70,97,107,101,65,112,112,46,99,111,109,112,108,105,99,
%%               97,116,105,111,110,48,14,12,12,99,111,109,112,108,105,
%%               99,97,116,105,111,110>>
%%
%% asn1rt_nif:decode_ber_tlv(ExtnValue) ->
%%  {{16,
%%    [{12,<<"com.example.FakeApp">>},
%%     {16,[{12,<<"app">>}]},
%%     {12,<<"com.example.FakeApp.voip">>},
%%     {16,[{12,<<"voip">>}]},
%%     {12,<<"com.example.FakeApp.complication">>},
%%     {16,[{12,<<"complication">>}]}]},
%%   <<>>}.
%%
-spec asn1_decode(Tlv) -> Result when
      Tlv :: undefined | binary(), Result :: {Decoded, Rest},
      Decoded :: term(), Rest :: binary().

asn1_decode(undefined) ->
    undefined;
asn1_decode(<<>>) ->
    throw({der_error, zero_data_length});
asn1_decode(<<Tlv/binary>>) ->
    %% Using undocumented (?) asn1rt_nif/1.
    {{Tag, Val}, Rest} = asn1rt_nif:decode_ber_tlv(Tlv),
    {unpack_tag_val(asn1_tag(Tag), Val), Rest}.

unpack_sequence([_|_] = Seq) ->
    unpack_sequence(Seq, []).

unpack_sequence([{Tag, Val}|T], Acc) ->
    UnpVal = unpack_tag_val(asn1_tag(Tag), Val),
    unpack_sequence(T, [UnpVal | Acc]);
unpack_sequence([], Acc) ->
    lists:reverse(Acc).

unpack_tag_val('BOOLEAN', Val)           -> unpack_boolean(Val);
unpack_tag_val('INTEGER', Val)           -> unpack_integer(Val);
unpack_tag_val('BIT STRING', Val)        -> unpack_bit_string(Val);
unpack_tag_val('OCTET STRING', Val)      -> unpack_octet_string(Val);
unpack_tag_val('NULL', Val)              -> unpack_null(Val);
unpack_tag_val('OBJECT IDENTIFIER', Val) -> unpack_object_identifier(Val);
unpack_tag_val('UTF8String', Val)        -> unpack_utf8_string(Val);
unpack_tag_val('SEQUENCE', Val)          -> unpack_sequence(Val);
unpack_tag_val('PrintableString', Val)   -> unpack_printable_string(Val);
unpack_tag_val('TeletexString', Val)     -> unpack_teletex_string(Val);
unpack_tag_val('IA5String', Val)         -> unpack_ia5_string(Val);
unpack_tag_val('BMPString', Val)         -> unpack_bmp_string(Val).

%%--------------------------------------------------------------------
unpack_boolean(<<0>>)     -> false;
unpack_boolean(<<16#FF>>) -> true.

%%--------------------------------------------------------------------
unpack_integer(Val) ->
    binary_to_integer(Val).

%%--------------------------------------------------------------------
unpack_bit_string(Val) ->
    Val.

%%--------------------------------------------------------------------
unpack_octet_string(Val) ->
    Val.

%%--------------------------------------------------------------------
unpack_null(Val) ->
    Val.

%%--------------------------------------------------------------------
unpack_object_identifier(Val) ->
    decode_object_identifier(Val).

%%--------------------------------------------------------------------
unpack_utf8_string(Val) ->
    unicode:characters_to_binary(Val, utf8).

%%--------------------------------------------------------------------
unpack_printable_string(Val) ->
    Val.

%%--------------------------------------------------------------------
unpack_teletex_string(Val) ->
    Val.

%%--------------------------------------------------------------------
unpack_ia5_string(Val) ->
    Val.

%%--------------------------------------------------------------------
unpack_bmp_string(Val) ->
    Val.


%%--------------------------------------------------------------------
decode_object_identifier(<<OID/binary>>) ->
    decode_object_identifier(binary_to_list(OID), []).

%%--------------------------------------------------------------------
decode_object_identifier(L, Acc) ->
    {{N1, N2}, Rest} = decode_object_identifier_init(L),
    decode_object_identifier_rest(Rest, [$., i2l(N2), $., i2l(N1) | Acc]).

%%--------------------------------------------------------------------
decode_object_identifier_init([B0|T]) ->
    case B0 div 40 of
        N when N =:= 0; N =:= 1 ->
            {{N, B0 rem 40}, T};
        2 ->
            {{2, B0 - 80}, T}
    end.

%%--------------------------------------------------------------------
decode_object_identifier_rest([Byte], Acc) when ?bit7_clear(Byte) ->
    lists:reverse([i2l(Byte) | Acc]);
decode_object_identifier_rest([Byte|T], Acc) when ?bit7_clear(Byte) ->
    decode_object_identifier_rest(T, [$., i2l(Byte) | Acc]);
decode_object_identifier_rest([_|_] = L, Acc) ->
    {N, Rest} = decode_object_identifier_multibyte(L, 0),
    decode_object_identifier_rest(Rest, [$., i2l(N) | Acc]).

%%--------------------------------------------------------------------
decode_object_identifier_multibyte([N|T], Acc) when ?bit7_set(N) ->
    decode_object_identifier_multibyte(T, shift7_and_add(Acc, N));
decode_object_identifier_multibyte([N|T], Acc) -> % end of multibyte seq
    {shift7_and_add(Acc, N), T}.

%%--------------------------------------------------------------------
-compile({inline, [{i2l, 1}]}).
i2l(N) -> integer_to_list(N).

%%--------------------------------------------------------------------
-compile({inline, [{bit8_clear, 1}]}).
bit8_clear(N) ->
    N band 16#7F.

%%--------------------------------------------------------------------
-compile({inline, [{shift7_and_add, 2}]}).
shift7_and_add(Sum, N) ->
    (Sum bsl 7) bor bit8_clear(N).

%%--------------------------------------------------------------------
-spec asn1_tag_val(TagName) -> TagNum when
      TagName :: atom(), TagNum :: asn1_tag().
asn1_tag_val('BOOLEAN'          ) -> 16#01;
asn1_tag_val('INTEGER'          ) -> 16#02;
asn1_tag_val('BIT STRING'       ) -> 16#03;
asn1_tag_val('OCTET STRING'     ) -> 16#04;
asn1_tag_val('NULL'             ) -> 16#05;
asn1_tag_val('OBJECT IDENTIFIER') -> 16#06;
asn1_tag_val('UTF8String'       ) -> 16#0C;
asn1_tag_val('SEQUENCE'         ) -> 16#10;
asn1_tag_val('PrintableString'  ) -> 16#13;
asn1_tag_val('TeletexString'    ) -> 16#14;
asn1_tag_val('IA5String'        ) -> 16#16;
asn1_tag_val('BMPString'        ) -> 16#1E;
asn1_tag_val(TagName            ) -> throw({unhandled_tag_name, TagName}).

%%--------------------------------------------------------------------
-spec asn1_tag(TagNum) -> TagName when
      TagNum :: asn1_tag(), TagName :: atom().

asn1_tag(16#01) -> 'BOOLEAN';
asn1_tag(16#02) -> 'INTEGER';
asn1_tag(16#03) -> 'BIT STRING';
asn1_tag(16#04) -> 'OCTET STRING';
asn1_tag(16#05) -> 'NULL';
asn1_tag(16#06) -> 'OBJECT IDENTIFIER';
asn1_tag(16#0C) -> 'UTF8String';
asn1_tag(16#10) -> 'SEQUENCE';
asn1_tag(16#13) -> 'PrintableString';
asn1_tag(16#14) -> 'TeletexString';
asn1_tag(16#16) -> 'IA5String';
asn1_tag(16#1E) -> 'BMPString';
asn1_tag(Tag)   -> throw({unhandled_asn1_tag, Tag}).

%%--------------------------------------------------------------------
-spec rearrange_topics(list()) -> list().

rearrange_topics([<<TopicName/binary>>, [<<TopicType/binary>>]|T]) ->
    [{TopicName, TopicType} | rearrange_topics(T)];
rearrange_topics([]) ->
    [].

