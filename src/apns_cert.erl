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
        , asn1_decode_tag/2
        , asn1_decode_sequence/2
        , asn1_tag_octets/1
        , asn1_tag_number/2
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

%% Last submatch must be either BundleSeedID:BundleID or just BundleID
-define(APP_ID_RE,
        "^Apple(?:\\s+Production|Development)?(?:\\s+IOS)?\\s+Push\\s+Services:\\s+(.*)$").

-define(APP_ID_RE_VOIP, "^VoIP\\s+Services:\\s+(.*)").

-define(WWDR_NAME,
    <<"Apple Worldwide Developer Relations Certification Authority">>).

-define(is_digit(X), ($0 =< X andalso X =< $9)).

%%--------------------------------------------------------------------
%% ASN.1 record defs
%%--------------------------------------------------------------------
-type asn1_class()    :: universal | application | context | private.
-type asn1_encoding() :: primitive | constructed.
-type asn1_tag_num() :: non_neg_integer().
-type asn1_tag_id() :: atom().

-record(asn1_tag, {
          class = universal :: asn1_class(),
          encoding = primitive :: asn1_encoding(),
          tag_num = 0 :: asn1_tag_num(),
          id = undefined :: asn1_tag_id()
         }).

-type asn1_tag() :: #asn1_tag{}.
-type asn1_len() :: non_neg_integer().
-type asn1_val() :: binary().

-record(asn1_tlv, {tag = #asn1_tag{} :: asn1_tag(),
                   len = 0 :: asn1_len(),
                   val = <<>> :: asn1_val()}).

-type asn1_tlv_rec() :: #asn1_tlv{}.

%%-------------------------------------------------------------------
%% Types
%%-------------------------------------------------------------------
-type bin_or_string() :: binary() | string().
-type special_string() ::
    {teletexString, bin_or_string()} | {printableString, bin_or_string()} |
    {universalString, bin_or_string()} | {utf8String, bin_or_string()} |
    {bmpString, bin_or_string()}.
-type cert_info() :: term().

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
    case re:run(Str, ?APP_ID_RE, [{capture, all_but_first, binary}]) of
        {match, [BundleInfo]} ->
            {ok, BundleInfo};
        nomatch ->
            case re:run(Str, ?APP_ID_RE_VOIP, [{capture,
                                                all_but_first,
                                                binary}]) of
                {match, [BundleInfo]} ->
                    {ok, BundleInfo}; % Assume prod for now
                nomatch ->
                    {error, {not_an_apns_cert, Str}}
            end
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
    maybe_extract_topics(?'id-apns-topics', ExtVals);
select_ext(ExtID, ExtVals) ->
    decode_ext(extract_ext(ExtID, ExtVals)).

%%--------------------------------------------------------------------
maybe_extract_topics(ExtID, ExtVals) ->
    case extract_ext(ExtID, ExtVals) of
        undefined ->
            undefined;
        EncodedTopics ->
            {Topics, _} = asn1_decode(EncodedTopics),
            Topics
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
asn1_decode(undefined) ->
    undefined;
asn1_decode(<<>>) ->
    throw({der_error, zero_data_length});
asn1_decode(<<T, Rest0/binary>>) ->
    {Res, Left} = case asn1_decode_tag(T, Rest0) of
                      {#asn1_tlv{tag=#asn1_tag{id='SEQUENCE'}}=Tlv, Rest} ->
                          Bytes = Tlv#asn1_tlv.val,
                          SeqLen = Tlv#asn1_tlv.len,
                          {asn1_decode_sequence(Bytes, SeqLen), Rest};
                      {#asn1_tlv{} = Tlv, Rest} ->
                          {asn1_decode_tlv(Tlv), Rest}
                  end,
    {canonicalize(Res), Left}.

%%--------------------------------------------------------------------
asn1_decode_tag(T, <<Rest0/binary>>) ->
    TagClass = asn1_class((T band 2#11000000) bsr 6),
    TagEncoding = asn1_encoding((T band 2#00100000) bsr 5),
    {TagNumber, Rest} = asn1_tag_number(T band 2#00011111, Rest0),
    Asn1Tag = #asn1_tag{
                 class = TagClass,
                 encoding = TagEncoding,
                 tag_num = TagNumber,
                 id = asn1_tag(TagNumber)
                },
    {Length, Rest1} = asn1_length_octets(Rest),
    <<Raw:Length/binary, Rest2/binary>> = Rest1,
    Asn1Tlv = #asn1_tlv{tag = Asn1Tag,
                        len = Length,
                        val = Raw},
    {Asn1Tlv, Rest2}.

%%--------------------------------------------------------------------
asn1_class(0) -> universal;
asn1_class(1) -> application;
asn1_class(2) -> context;
asn1_class(3) -> private.

%%--------------------------------------------------------------------
asn1_encoding(0) -> primitive;
asn1_encoding(1) -> constructed.

%%--------------------------------------------------------------------
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
asn1_tag(Tag)   -> Tag.

%%--------------------------------------------------------------------
asn1_length_octets(<<L, _/binary>>) when ?asn1_indefinite_form(L) ->
    throw({der_error, indefinite_length_form_not_allowed});
asn1_length_octets(<<L, Data/binary>>) when ?asn1_short_form(L) ->
    {L, Data};
asn1_length_octets(<<L, Data/binary>>) when ?asn1_long_form(L) ->
    NumOctets = (L band 2#01111111),
    <<Len:NumOctets/big-unit:8, Rest/binary>> = Data,
    {Len, Rest}.

%%--------------------------------------------------------------------
asn1_tag_number(N, <<Rest/binary>>) when 0 =< N, N < 30 ->
    {N, Rest};
asn1_tag_number(N, <<Rest/binary>>) when N >= 31 ->
    % Find all octets in Rest with bit 8 == 1. The last octet
    % will have bit 8 == 0. The value is the concatenation of
    % the lower 7 bits of all these octets.
    asn1_tag_octets(Rest, 0).

%%--------------------------------------------------------------------
asn1_tag_octets(<<Octets/binary>>) ->
    asn1_tag_octets(Octets, 0).

asn1_tag_octets(<<O, Rest/binary>>, Sum0) when O band 2#10000000 /= 0 ->
    Sum = (Sum0 bsl 7) bor (O band 2#01111111),
    asn1_tag_octets(Rest, Sum);
asn1_tag_octets(<<O, Rest/binary>>, Sum0) when O band 2#10000000 == 0 ->
    {(Sum0 bsl 7) bor (O band 2#01111111), Rest};
asn1_tag_octets(<<Data/binary>>, _Sum) ->
    throw({der_error, {invalid_tag_octets, Data}}).

%%--------------------------------------------------------------------
-spec asn1_decode_sequence(Bytes, SeqLen) -> {Seq, Rest} when
      Bytes :: binary(), SeqLen :: integer(),
      Seq :: [asn1_tlv_rec()], Rest :: binary().
asn1_decode_sequence(<<Bytes/binary>>, SeqLen) ->
    asn1_decode_sequence(Bytes, [], SeqLen).

asn1_decode_sequence(<<Rest/binary>>, Acc, 0) ->
    {[asn1_decode_tlv(Tlv) || Tlv <- lists:reverse(Acc)], Rest};
asn1_decode_sequence(<<Bytes/binary>>, Acc, SeqLen) ->
    case asn1_decode(Bytes) of
        {Asn1Tlv, <<Rest/bytes>>} ->
            BytesDecoded = byte_size(Bytes) - byte_size(Rest),
            asn1_decode_sequence(Rest, [Asn1Tlv | Acc], SeqLen - BytesDecoded);
        [{_T,_L,_V}] = Seq ->
            asn1_decode_sequence(<<>>, [Seq | Acc], 0);
        {_T,_L,_V} = Tlv ->
            asn1_decode_sequence(<<>>, [Tlv | Acc], 0)
    end.


%%--------------------------------------------------------------------
asn1_decode_tlv(#asn1_tlv{tag=Tag, len=Len, val=Val}) ->
    asn1_decode_tlv(Tag, Len, Val);
asn1_decode_tlv({Tag, Len, Val}) ->
    asn1_decode_prim(Tag, Len, Val);
asn1_decode_tlv([{Tag, Len, Val}]) ->
    {Tag, Len, Val};
asn1_decode_tlv({[{T, L, V}], <<>>}) ->
    {[asn1_decode_prim(T, L, V)]};
asn1_decode_tlv({[_|_] = List, Rest}) ->
    {[asn1_decode_prim(T, L, V) || {T, L, V} <- List], Rest}.


%%--------------------------------------------------------------------
asn1_decode_tlv(#asn1_tag{id=Id}, Len, Val) when Id == 'UTF8String' orelse
                                                 Id == 'PrintableString' orelse
                                                 Id == 'TeletexString' orelse
                                                 Id == 'IA5String' orelse
                                                 Id == 'BMPString' ->
    asn1_decode_prim(Id, Len, Val);
asn1_decode_tlv(#asn1_tag{id='SEQUENCE'}, Len, Val) ->
    Seq = asn1_decode_sequence(Val, Len),
    [asn1_decode_tlv(Tlv) || #asn1_tlv{} = Tlv <- Seq].


%%--------------------------------------------------------------------
asn1_decode_prim('UTF8String' = Tag, Len, Val) ->
    {Tag, Len, unicode:characters_to_binary(Val, utf8)};
asn1_decode_prim('PrintableString' = Tag, Len, Val) ->
    {Tag, Len, Val};
asn1_decode_prim('TeletexString' = Tag, Len, Val) ->
    {Tag, Len, Val};
asn1_decode_prim('IA5String' = Tag, Len, Val) ->
    {Tag, Len, Val};
asn1_decode_prim('BMPString' = Tag, Len, Val) ->
    {Tag, Len, Val};
asn1_decode_prim(Tag, Len, Val) ->
    throw({der_error, {unhandled_tlv, {Tag, Len, Val}}}).

%%--------------------------------------------------------------------
canonicalize({Internal, <<>>}) ->
    canonicalize(Internal);
canonicalize([{_,_,V1},{_,_,V2}|T]) ->
    [{V1, V2}|canonicalize(T)];
canonicalize([{_,_,_}]=L) ->
    L;
canonicalize({_,_,_}=T) ->
    T;
canonicalize([]) ->
    [].

