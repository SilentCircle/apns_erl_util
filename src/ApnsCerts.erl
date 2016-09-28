%% Generated by the Erlang ASN.1 BER_V2-compiler version, utilizing bit-syntax:4.0.2
%% Purpose: encoder and decoder to the types in mod ApnsCerts

-module('ApnsCerts').
-compile(nowarn_unused_vars).
-dialyzer(no_improper_lists).
-include("ApnsCerts.hrl").
-asn1_info([{vsn,'4.0.2'},
            {module,'ApnsCerts'},
            {options,[{i,"src"},
 {asn_dir,"asn1"},
 {asndir,"asn1"},
 ber,der,noobj,
 {outdir,"src"},
 {i,"."},
 {i,"/home/efine/work/sc/apns_erl_util/asn1"}]}]).

-export([encoding_rule/0,bit_string_format/0,
         legacy_erlang_types/0]).
-export(['dialyzer-suppressions'/1]).
-export([
'enc_ApplePushExtension'/2,
'enc_ApnsDevelopment'/2,
'enc_ApnsProduction'/2,
'enc_ApnsBundleID'/2,
'enc_ApnsBundleInfo'/2,
'enc_ApnsTopics'/2,
'enc_ApnsTopic'/2,
'enc_ApnsTopicName'/2,
'enc_ApnsTopicType'/2,
'enc_TBoolean'/2,
'enc_TInteger'/2,
'enc_TBitString'/2,
'enc_TOctetString'/2,
'enc_TNull'/2,
'enc_TObjectIdentifier'/2,
'enc_TUTF8String'/2,
'enc_TPrintableString'/2,
'enc_TTeletexString'/2,
'enc_TIA5String'/2,
'enc_TBMPString'/2
]).

-export([
'dec_ApplePushExtension'/2,
'dec_ApnsDevelopment'/2,
'dec_ApnsProduction'/2,
'dec_ApnsBundleID'/2,
'dec_ApnsBundleInfo'/2,
'dec_ApnsTopics'/2,
'dec_ApnsTopic'/2,
'dec_ApnsTopicName'/2,
'dec_ApnsTopicType'/2,
'dec_TBoolean'/2,
'dec_TInteger'/2,
'dec_TBitString'/2,
'dec_TOctetString'/2,
'dec_TNull'/2,
'dec_TObjectIdentifier'/2,
'dec_TUTF8String'/2,
'dec_TPrintableString'/2,
'dec_TTeletexString'/2,
'dec_TIA5String'/2,
'dec_TBMPString'/2
]).

-export([
'push-certs'/0,
'id-apns-development'/0,
'id-apns-production'/0,
'id-apns-bundle-id'/0,
'id-apns-bundle-info'/0,
'id-apns-topics'/0
]).

-export([
'enc_apnsDevelopment'/3,
'enc_apnsProduction'/3,
'enc_apnsBundleID'/3,
'enc_apnsBundleInfo'/3,
'enc_apnsTopics'/3
]).

-export([
'dec_apnsDevelopment'/3,
'dec_apnsProduction'/3,
'dec_apnsBundleID'/3,
'dec_apnsBundleInfo'/3,
'dec_apnsTopics'/3
]).

-export([
'getenc_SupportedExtensions'/1
]).

-export([
'getdec_SupportedExtensions'/1
]).

-export([info/0]).


-export([encode/2,decode/2]).

encoding_rule() -> ber.

bit_string_format() -> bitstring.

legacy_erlang_types() -> false.

encode(Type, Data) ->
try iolist_to_binary(element(1, encode_disp(Type, Data))) of
  Bytes ->
    {ok,Bytes}
  catch
    Class:Exception when Class =:= error; Class =:= exit ->
      case Exception of
        {error,Reason}=Error ->
          Error;
        Reason ->
         {error,{asn1,Reason}}
      end
end.

decode(Type,Data) ->
try decode_disp(Type, element(1, ber_decode_nif(Data))) of
  Result ->
    {ok,Result}
  catch
    Class:Exception when Class =:= error; Class =:= exit ->
      case Exception of
        {error,Reason}=Error ->
          Error;
        Reason ->
         {error,{asn1,Reason}}
      end
end.

encode_disp('ApplePushExtension',Data) -> 'enc_ApplePushExtension'(Data);
encode_disp('ApnsDevelopment',Data) -> 'enc_ApnsDevelopment'(Data);
encode_disp('ApnsProduction',Data) -> 'enc_ApnsProduction'(Data);
encode_disp('ApnsBundleID',Data) -> 'enc_ApnsBundleID'(Data);
encode_disp('ApnsBundleInfo',Data) -> 'enc_ApnsBundleInfo'(Data);
encode_disp('ApnsTopics',Data) -> 'enc_ApnsTopics'(Data);
encode_disp('ApnsTopic',Data) -> 'enc_ApnsTopic'(Data);
encode_disp('ApnsTopicName',Data) -> 'enc_ApnsTopicName'(Data);
encode_disp('ApnsTopicType',Data) -> 'enc_ApnsTopicType'(Data);
encode_disp('TBoolean',Data) -> 'enc_TBoolean'(Data);
encode_disp('TInteger',Data) -> 'enc_TInteger'(Data);
encode_disp('TBitString',Data) -> 'enc_TBitString'(Data);
encode_disp('TOctetString',Data) -> 'enc_TOctetString'(Data);
encode_disp('TNull',Data) -> 'enc_TNull'(Data);
encode_disp('TObjectIdentifier',Data) -> 'enc_TObjectIdentifier'(Data);
encode_disp('TUTF8String',Data) -> 'enc_TUTF8String'(Data);
encode_disp('TPrintableString',Data) -> 'enc_TPrintableString'(Data);
encode_disp('TTeletexString',Data) -> 'enc_TTeletexString'(Data);
encode_disp('TIA5String',Data) -> 'enc_TIA5String'(Data);
encode_disp('TBMPString',Data) -> 'enc_TBMPString'(Data);
encode_disp(Type,_Data) -> exit({error,{asn1,{undefined_type,Type}}}).


decode_disp('ApplePushExtension',Data) -> 'dec_ApplePushExtension'(Data);
decode_disp('ApnsDevelopment',Data) -> 'dec_ApnsDevelopment'(Data);
decode_disp('ApnsProduction',Data) -> 'dec_ApnsProduction'(Data);
decode_disp('ApnsBundleID',Data) -> 'dec_ApnsBundleID'(Data);
decode_disp('ApnsBundleInfo',Data) -> 'dec_ApnsBundleInfo'(Data);
decode_disp('ApnsTopics',Data) -> 'dec_ApnsTopics'(Data);
decode_disp('ApnsTopic',Data) -> 'dec_ApnsTopic'(Data);
decode_disp('ApnsTopicName',Data) -> 'dec_ApnsTopicName'(Data);
decode_disp('ApnsTopicType',Data) -> 'dec_ApnsTopicType'(Data);
decode_disp('TBoolean',Data) -> 'dec_TBoolean'(Data);
decode_disp('TInteger',Data) -> 'dec_TInteger'(Data);
decode_disp('TBitString',Data) -> 'dec_TBitString'(Data);
decode_disp('TOctetString',Data) -> 'dec_TOctetString'(Data);
decode_disp('TNull',Data) -> 'dec_TNull'(Data);
decode_disp('TObjectIdentifier',Data) -> 'dec_TObjectIdentifier'(Data);
decode_disp('TUTF8String',Data) -> 'dec_TUTF8String'(Data);
decode_disp('TPrintableString',Data) -> 'dec_TPrintableString'(Data);
decode_disp('TTeletexString',Data) -> 'dec_TTeletexString'(Data);
decode_disp('TIA5String',Data) -> 'dec_TIA5String'(Data);
decode_disp('TBMPString',Data) -> 'dec_TBMPString'(Data);
decode_disp(Type,_Data) -> exit({error,{asn1,{undefined_type,Type}}}).




info() ->
   case ?MODULE:module_info(attributes) of
     Attributes when is_list(Attributes) ->
       case lists:keyfind(asn1_info, 1, Attributes) of
         {_,Info} when is_list(Info) ->
           Info;
         _ ->
           []
       end;
     _ ->
       []
   end.


%%================================
%%  ApplePushExtension
%%================================
'enc_ApplePushExtension'(Val) ->
    'enc_ApplePushExtension'(Val, [<<48>>]).

'enc_ApplePushExtension'(Val, TagIn) ->
{_,Cindex1, Cindex2, Cindex3} = Val,
ObjextnID = 
   'ApnsCerts':'getenc_SupportedExtensions'(                                   Cindex1),

%%-------------------------------------------------
%% attribute extnID(1) with type OBJECT IDENTIFIER
%%-------------------------------------------------
   {EncBytes1,EncLen1} = encode_object_identifier(Cindex1, [<<6>>]),

%%-------------------------------------------------
%% attribute critical(2) with type BOOLEAN DEFAULT = false
%%-------------------------------------------------
   {EncBytes2,EncLen2} =  case is_default_1(Cindex2) of
true -> {[],0};
false ->
encode_boolean(Cindex2, [<<1>>])
       end,

%%-------------------------------------------------
%% attribute extnValue(3) with type typefieldType
%%-------------------------------------------------
   {TmpBytes3,_} = ObjextnID('Type', Cindex3, []),
   {EncBytes3,EncLen3} = encode_open_type(TmpBytes3, [])
,

   BytesSoFar = [EncBytes1, EncBytes2, EncBytes3],
LenSoFar = EncLen1 + EncLen2 + EncLen3,
encode_tags(TagIn, BytesSoFar, LenSoFar).


'dec_ApplePushExtension'(Tlv) ->
   'dec_ApplePushExtension'(Tlv, [16]).

'dec_ApplePushExtension'(Tlv, TagIn) ->
   %%-------------------------------------------------
   %% decode tag and length 
   %%-------------------------------------------------
Tlv1 = match_tags(Tlv, TagIn),

%%-------------------------------------------------
%% attribute extnID(1) with type OBJECT IDENTIFIER
%%-------------------------------------------------
[V1|Tlv2] = Tlv1, 
Term1 = decode_object_identifier(V1, [6]),

%%-------------------------------------------------
%% attribute critical(2) with type BOOLEAN DEFAULT = false
%%-------------------------------------------------
{Term2,Tlv3} = case Tlv2 of
[{1,V2}|TempTlv3] ->
    {decode_boolean(V2, []), TempTlv3};
    _ ->
        {false,Tlv2}
end,

%%-------------------------------------------------
%% attribute extnValue(3) with type typefieldType
%%-------------------------------------------------
[V3|Tlv4] = Tlv3, 

  Tmpterm1 = decode_open_type(V3, []),

DecObjextnIDTerm1 =
   'ApnsCerts':'getdec_SupportedExtensions'(Term1),
Term3 = 
   case (catch DecObjextnIDTerm1('Type', Tmpterm1, [])) of
      {'EXIT', Reason1} ->
         exit({'Type not compatible with table constraint',Reason1});
      Tmpterm2 ->
         Tmpterm2
   end,

case Tlv4 of
[] -> true;_ -> exit({error,{asn1, {unexpected,Tlv4}}}) % extra fields not allowed
end,
   {'ApplePushExtension', Term1, Term2, Term3}.



%%================================
%%  ApnsDevelopment
%%================================
'enc_ApnsDevelopment'(Val) ->
    'enc_ApnsDevelopment'(Val, [<<5>>]).

'enc_ApnsDevelopment'(Val, TagIn) ->
encode_null(Val, TagIn).


'dec_ApnsDevelopment'(Tlv) ->
   'dec_ApnsDevelopment'(Tlv, [5]).

'dec_ApnsDevelopment'(Tlv, TagIn) ->
decode_null(Tlv, TagIn).



%%================================
%%  ApnsProduction
%%================================
'enc_ApnsProduction'(Val) ->
    'enc_ApnsProduction'(Val, [<<5>>]).

'enc_ApnsProduction'(Val, TagIn) ->
encode_null(Val, TagIn).


'dec_ApnsProduction'(Tlv) ->
   'dec_ApnsProduction'(Tlv, [5]).

'dec_ApnsProduction'(Tlv, TagIn) ->
decode_null(Tlv, TagIn).



%%================================
%%  ApnsBundleID
%%================================
'enc_ApnsBundleID'(Val) ->
    'enc_ApnsBundleID'(Val, [<<12>>]).

'enc_ApnsBundleID'(Val, TagIn) ->
encode_UTF8_string(Val, TagIn).


'dec_ApnsBundleID'(Tlv) ->
   'dec_ApnsBundleID'(Tlv, [12]).

'dec_ApnsBundleID'(Tlv, TagIn) ->
decode_UTF8_string(Tlv, TagIn).



%%================================
%%  ApnsBundleInfo
%%================================
'enc_ApnsBundleInfo'(Val) ->
    'enc_ApnsBundleInfo'(Val, [<<12>>]).

'enc_ApnsBundleInfo'(Val, TagIn) ->
encode_UTF8_string(Val, TagIn).


'dec_ApnsBundleInfo'(Tlv) ->
   'dec_ApnsBundleInfo'(Tlv, [12]).

'dec_ApnsBundleInfo'(Tlv, TagIn) ->
decode_UTF8_string(Tlv, TagIn).



%%================================
%%  ApnsTopics
%%================================
'enc_ApnsTopics'(Val) ->
    'enc_ApnsTopics'(Val, [<<48>>]).

'enc_ApnsTopics'(Val, TagIn) ->
   {EncBytes,EncLen} = 'enc_ApnsTopics_components'(Val,[],0),
   encode_tags(TagIn, EncBytes, EncLen).

'enc_ApnsTopics_components'([], AccBytes, AccLen) -> 
   {lists:reverse(AccBytes),AccLen};

'enc_ApnsTopics_components'([H|T],AccBytes, AccLen) ->
   {EncBytes,EncLen} = 'enc_ApnsTopic'(H, []),
   'enc_ApnsTopics_components'(T,[EncBytes|AccBytes], AccLen + EncLen).



'dec_ApnsTopics'(Tlv) ->
   'dec_ApnsTopics'(Tlv, [16]).

'dec_ApnsTopics'(Tlv, TagIn) ->
   %%-------------------------------------------------
   %% decode tag and length 
   %%-------------------------------------------------
Tlv1 = match_tags(Tlv, TagIn),
['dec_ApnsTopic'(V1, []) || V1 <- Tlv1].




%%================================
%%  ApnsTopic
%%================================
'enc_ApnsTopic'(Val) ->
    'enc_ApnsTopic'(Val, []).

'enc_ApnsTopic'(Val, TagIn) ->
   {EncBytes,EncLen} = case element(1,Val) of
      name ->
         encode_UTF8_string(element(2,Val), [<<12>>]);
      type ->
         'enc_ApnsTopicType'(element(2,Val), [<<48>>]);
      Else -> 
         exit({error,{asn1,{invalid_choice_type,Else}}})
   end,

encode_tags(TagIn, EncBytes, EncLen).




'dec_ApnsTopic'(Tlv) ->
   'dec_ApnsTopic'(Tlv, []).

'dec_ApnsTopic'(Tlv, TagIn) ->
Tlv1 = match_tags(Tlv, TagIn),
case (case Tlv1 of [CtempTlv1] -> CtempTlv1; _ -> Tlv1 end) of

%% 'name'
    {12, V1} -> 
        {name, decode_UTF8_string(V1, [])};


%% 'type'
    {16, V1} -> 
        {type, 'dec_ApnsTopicType'(V1, [])};

      Else -> 
         exit({error,{asn1,{invalid_choice_tag,Else}}})
   end
.


%%================================
%%  ApnsTopicName
%%================================
'enc_ApnsTopicName'(Val) ->
    'enc_ApnsTopicName'(Val, [<<12>>]).

'enc_ApnsTopicName'(Val, TagIn) ->
encode_UTF8_string(Val, TagIn).


'dec_ApnsTopicName'(Tlv) ->
   'dec_ApnsTopicName'(Tlv, [12]).

'dec_ApnsTopicName'(Tlv, TagIn) ->
decode_UTF8_string(Tlv, TagIn).



%%================================
%%  ApnsTopicType
%%================================
'enc_ApnsTopicType'(Val) ->
    'enc_ApnsTopicType'(Val, [<<48>>]).

'enc_ApnsTopicType'(Val, TagIn) ->
{_,Cindex1} = Val,

%%-------------------------------------------------
%% attribute name(1) with type UTF8String
%%-------------------------------------------------
   {EncBytes1,EncLen1} = encode_UTF8_string(Cindex1, [<<12>>]),

   BytesSoFar = [EncBytes1],
LenSoFar = EncLen1,
encode_tags(TagIn, BytesSoFar, LenSoFar).


'dec_ApnsTopicType'(Tlv) ->
   'dec_ApnsTopicType'(Tlv, [16]).

'dec_ApnsTopicType'(Tlv, TagIn) ->
   %%-------------------------------------------------
   %% decode tag and length 
   %%-------------------------------------------------
Tlv1 = match_tags(Tlv, TagIn),

%%-------------------------------------------------
%% attribute name(1) with type UTF8String
%%-------------------------------------------------
[V1|Tlv2] = Tlv1, 
Term1 = decode_UTF8_string(V1, [12]),

case Tlv2 of
[] -> true;_ -> exit({error,{asn1, {unexpected,Tlv2}}}) % extra fields not allowed
end,
   {'ApnsTopicType', Term1}.



%%================================
%%  TBoolean
%%================================
'enc_TBoolean'(Val) ->
    'enc_TBoolean'(Val, [<<1>>]).

'enc_TBoolean'(Val, TagIn) ->
encode_boolean(Val, TagIn).


'dec_TBoolean'(Tlv) ->
   'dec_TBoolean'(Tlv, [1]).

'dec_TBoolean'(Tlv, TagIn) ->
decode_boolean(Tlv, TagIn).



%%================================
%%  TInteger
%%================================
'enc_TInteger'(Val) ->
    'enc_TInteger'(Val, [<<2>>]).

'enc_TInteger'(Val, TagIn) ->
encode_integer(Val, TagIn).


'dec_TInteger'(Tlv) ->
   'dec_TInteger'(Tlv, [2]).

'dec_TInteger'(Tlv, TagIn) ->
decode_integer(Tlv, TagIn).



%%================================
%%  TBitString
%%================================
'enc_TBitString'(Val) ->
    'enc_TBitString'(Val, [<<3>>]).

'enc_TBitString'(Val, TagIn) ->
encode_unnamed_bit_string(Val, TagIn).


'dec_TBitString'(Tlv) ->
   'dec_TBitString'(Tlv, [3]).

'dec_TBitString'(Tlv, TagIn) ->
decode_native_bit_string(Tlv, TagIn).



%%================================
%%  TOctetString
%%================================
'enc_TOctetString'(Val) ->
    'enc_TOctetString'(Val, [<<4>>]).

'enc_TOctetString'(Val, TagIn) ->
encode_restricted_string(Val, TagIn).


'dec_TOctetString'(Tlv) ->
   'dec_TOctetString'(Tlv, [4]).

'dec_TOctetString'(Tlv, TagIn) ->
decode_octet_string(Tlv, TagIn).



%%================================
%%  TNull
%%================================
'enc_TNull'(Val) ->
    'enc_TNull'(Val, [<<5>>]).

'enc_TNull'(Val, TagIn) ->
encode_null(Val, TagIn).


'dec_TNull'(Tlv) ->
   'dec_TNull'(Tlv, [5]).

'dec_TNull'(Tlv, TagIn) ->
decode_null(Tlv, TagIn).



%%================================
%%  TObjectIdentifier
%%================================
'enc_TObjectIdentifier'(Val) ->
    'enc_TObjectIdentifier'(Val, [<<6>>]).

'enc_TObjectIdentifier'(Val, TagIn) ->
encode_object_identifier(Val, TagIn).


'dec_TObjectIdentifier'(Tlv) ->
   'dec_TObjectIdentifier'(Tlv, [6]).

'dec_TObjectIdentifier'(Tlv, TagIn) ->
decode_object_identifier(Tlv, TagIn).



%%================================
%%  TUTF8String
%%================================
'enc_TUTF8String'(Val) ->
    'enc_TUTF8String'(Val, [<<12>>]).

'enc_TUTF8String'(Val, TagIn) ->
encode_UTF8_string(Val, TagIn).


'dec_TUTF8String'(Tlv) ->
   'dec_TUTF8String'(Tlv, [12]).

'dec_TUTF8String'(Tlv, TagIn) ->
decode_UTF8_string(Tlv, TagIn).



%%================================
%%  TPrintableString
%%================================
'enc_TPrintableString'(Val) ->
    'enc_TPrintableString'(Val, [<<19>>]).

'enc_TPrintableString'(Val, TagIn) ->
encode_restricted_string(Val, TagIn).


'dec_TPrintableString'(Tlv) ->
   'dec_TPrintableString'(Tlv, [19]).

'dec_TPrintableString'(Tlv, TagIn) ->
begin
binary_to_list(decode_restricted_string(Tlv, TagIn))
end
.



%%================================
%%  TTeletexString
%%================================
'enc_TTeletexString'(Val) ->
    'enc_TTeletexString'(Val, [<<20>>]).

'enc_TTeletexString'(Val, TagIn) ->
encode_restricted_string(Val, TagIn).


'dec_TTeletexString'(Tlv) ->
   'dec_TTeletexString'(Tlv, [20]).

'dec_TTeletexString'(Tlv, TagIn) ->
begin
binary_to_list(decode_restricted_string(Tlv, TagIn))
end
.



%%================================
%%  TIA5String
%%================================
'enc_TIA5String'(Val) ->
    'enc_TIA5String'(Val, [<<22>>]).

'enc_TIA5String'(Val, TagIn) ->
encode_restricted_string(Val, TagIn).


'dec_TIA5String'(Tlv) ->
   'dec_TIA5String'(Tlv, [22]).

'dec_TIA5String'(Tlv, TagIn) ->
begin
binary_to_list(decode_restricted_string(Tlv, TagIn))
end
.



%%================================
%%  TBMPString
%%================================
'enc_TBMPString'(Val) ->
    'enc_TBMPString'(Val, [<<30>>]).

'enc_TBMPString'(Val, TagIn) ->
encode_BMP_string(Val, TagIn).


'dec_TBMPString'(Tlv) ->
   'dec_TBMPString'(Tlv, [30]).

'dec_TBMPString'(Tlv, TagIn) ->
decode_BMP_string(Tlv, TagIn).

'push-certs'() ->
{1,2,840,113635,100,6,3}.

'id-apns-development'() ->
{1,2,840,113635,100,6,3,1}.

'id-apns-production'() ->
{1,2,840,113635,100,6,3,2}.

'id-apns-bundle-id'() ->
{1,2,840,113635,100,6,3,3}.

'id-apns-bundle-info'() ->
{1,2,840,113635,100,6,3,4}.

'id-apns-topics'() ->
{1,2,840,113635,100,6,3,6}.




%%================================
%%  apnsDevelopment
%%================================
'enc_apnsDevelopment'('Type', Val, _RestPrimFieldName) ->
   'enc_ApnsDevelopment'(Val, [<<5>>]).


'dec_apnsDevelopment'('Type', Bytes,_) ->
  Tlv = tlv_format(Bytes),
   'dec_ApnsDevelopment'(Tlv, [5]).

tlv_format(Bytes) when is_binary(Bytes) ->
  {Tlv,_} = ber_decode_nif(Bytes),
  Tlv;
tlv_format(Bytes) ->
  Bytes.



%%================================
%%  apnsProduction
%%================================
'enc_apnsProduction'('Type', Val, _RestPrimFieldName) ->
   'enc_ApnsProduction'(Val, [<<5>>]).


'dec_apnsProduction'('Type', Bytes,_) ->
  Tlv = tlv_format(Bytes),
   'dec_ApnsProduction'(Tlv, [5]).




%%================================
%%  apnsBundleID
%%================================
'enc_apnsBundleID'('Type', Val, _RestPrimFieldName) ->
   'enc_ApnsBundleID'(Val, [<<12>>]).


'dec_apnsBundleID'('Type', Bytes,_) ->
  Tlv = tlv_format(Bytes),
   'dec_ApnsBundleID'(Tlv, [12]).




%%================================
%%  apnsBundleInfo
%%================================
'enc_apnsBundleInfo'('Type', Val, _RestPrimFieldName) ->
   'enc_ApnsBundleInfo'(Val, [<<12>>]).


'dec_apnsBundleInfo'('Type', Bytes,_) ->
  Tlv = tlv_format(Bytes),
   'dec_ApnsBundleInfo'(Tlv, [12]).




%%================================
%%  apnsTopics
%%================================
'enc_apnsTopics'('Type', Val, _RestPrimFieldName) ->
   'enc_ApnsTopics'(Val, [<<48>>]).


'dec_apnsTopics'('Type', Bytes,_) ->
  Tlv = tlv_format(Bytes),
   'dec_ApnsTopics'(Tlv, [16]).




%%================================
%%  SupportedExtensions
%%================================
'getenc_SupportedExtensions'({1,2,840,113635,100,6,3,1}) ->
    fun 'enc_apnsDevelopment'/3;
'getenc_SupportedExtensions'({1,2,840,113635,100,6,3,2}) ->
    fun 'enc_apnsProduction'/3;
'getenc_SupportedExtensions'({1,2,840,113635,100,6,3,3}) ->
    fun 'enc_apnsBundleID'/3;
'getenc_SupportedExtensions'({1,2,840,113635,100,6,3,4}) ->
    fun 'enc_apnsBundleInfo'/3;
'getenc_SupportedExtensions'({1,2,840,113635,100,6,3,6}) ->
    fun 'enc_apnsTopics'/3;
'getenc_SupportedExtensions'(ErrV) ->
   fun(C,V,_) -> exit({'Type not compatible with table constraint',{component,C},{value,V}, {unique_name_and_value,id, ErrV}}) end.

'getdec_SupportedExtensions'({1,2,840,113635,100,6,3,1}) ->
    fun 'dec_apnsDevelopment'/3;
'getdec_SupportedExtensions'({1,2,840,113635,100,6,3,2}) ->
    fun 'dec_apnsProduction'/3;
'getdec_SupportedExtensions'({1,2,840,113635,100,6,3,3}) ->
    fun 'dec_apnsBundleID'/3;
'getdec_SupportedExtensions'({1,2,840,113635,100,6,3,4}) ->
    fun 'dec_apnsBundleInfo'/3;
'getdec_SupportedExtensions'({1,2,840,113635,100,6,3,6}) ->
    fun 'dec_apnsTopics'/3;
'getdec_SupportedExtensions'(ErrV) ->
  fun(C,V,_) -> exit({{component,C},{value,V},{unique_name_and_value,id, ErrV}}) end.



%%%
%%% Run-time functions.
%%%

'dialyzer-suppressions'(Arg) ->
    ok.

is_default_1(asn1_DEFAULT) ->
true;
is_default_1(false) ->
true;
is_default_1(_) ->
false.


ber_decode_nif(B) ->
    asn1rt_nif:decode_ber_tlv(B).

collect_parts(TlvList) ->
    collect_parts(TlvList, []).

collect_parts([{_,L}|Rest], Acc) when is_list(L) ->
    collect_parts(Rest, [collect_parts(L)|Acc]);
collect_parts([{3,<<Unused,Bits/binary>>}|Rest], _Acc) ->
    collect_parts_bit(Rest, [Bits], Unused);
collect_parts([{_T,V}|Rest], Acc) ->
    collect_parts(Rest, [V|Acc]);
collect_parts([], Acc) ->
    list_to_binary(lists:reverse(Acc)).

collect_parts_bit([{3,<<Unused,Bits/binary>>}|Rest], Acc, Uacc) ->
    collect_parts_bit(Rest, [Bits|Acc], Unused + Uacc);
collect_parts_bit([], Acc, Uacc) ->
    list_to_binary([Uacc|lists:reverse(Acc)]).

dec_subidentifiers(<<>>, _Av, Al) ->
    lists:reverse(Al);
dec_subidentifiers(<<1:1,H:7,T/binary>>, Av, Al) ->
    dec_subidentifiers(T, Av bsl 7 + H, Al);
dec_subidentifiers(<<H,T/binary>>, Av, Al) ->
    dec_subidentifiers(T, 0, [Av bsl 7 + H|Al]).

decode_BMP_string(Buffer, Tags) ->
    Bin = match_and_collect(Buffer, Tags),
    mk_BMP_string(binary_to_list(Bin)).

decode_UTF8_string(Tlv, TagsIn) ->
    Val = match_tags(Tlv, TagsIn),
    case Val of
        [_|_] = PartList ->
            collect_parts(PartList);
        Bin ->
            Bin
    end.

decode_boolean(Tlv, TagIn) ->
    Val = match_tags(Tlv, TagIn),
    case Val of
        <<0:8>> ->
            false;
        <<_:8>> ->
            true;
        _ ->
            exit({error,{asn1,{decode_boolean,Val}}})
    end.

decode_integer(Tlv, TagIn) ->
    Bin = match_tags(Tlv, TagIn),
    Len = byte_size(Bin),
    <<Int:Len/signed-unit:8>> = Bin,
    Int.

decode_native_bit_string(Buffer, Tags) ->
    case match_and_collect(Buffer, Tags) of
        <<0>> ->
            <<>>;
        <<Unused,Bits/binary>> ->
            Size = bit_size(Bits) - Unused,
            <<Val:Size/bitstring,_:Unused/bitstring>> = Bits,
            Val
    end.

decode_null(Tlv, Tags) ->
    Val = match_tags(Tlv, Tags),
    case Val of
        <<>> ->
            'NULL';
        _ ->
            exit({error,{asn1,{decode_null,Val}}})
    end.

decode_object_identifier(Tlv, Tags) ->
    Val = match_tags(Tlv, Tags),
    [AddedObjVal|ObjVals] = dec_subidentifiers(Val, 0, []),
    {Val1,Val2} =
        if
            AddedObjVal < 40 ->
                {0,AddedObjVal};
            AddedObjVal < 80 ->
                {1,AddedObjVal - 40};
            true ->
                {2,AddedObjVal - 80}
        end,
    list_to_tuple([Val1,Val2|ObjVals]).

decode_octet_string(Tlv, TagsIn) ->
    Bin = match_and_collect(Tlv, TagsIn),
    binary:copy(Bin).

decode_open_type(Tlv, TagIn) ->
    case match_tags(Tlv, TagIn) of
        Bin when is_binary(Bin) ->
            {InnerTlv,_} = ber_decode_nif(Bin),
            InnerTlv;
        TlvBytes ->
            TlvBytes
    end.

decode_restricted_string(Tlv, TagsIn) ->
    match_and_collect(Tlv, TagsIn).

e_object_identifier({'OBJECT IDENTIFIER',V}) ->
    e_object_identifier(V);
e_object_identifier(V) when is_tuple(V) ->
    e_object_identifier(tuple_to_list(V));
e_object_identifier([E1,E2|Tail]) ->
    Head = 40 * E1 + E2,
    {H,Lh} = mk_object_val(Head),
    {R,Lr} = lists:mapfoldl(fun enc_obj_id_tail/2, 0, Tail),
    {[H|R],Lh + Lr}.

enc_obj_id_tail(H, Len) ->
    {B,L} = mk_object_val(H),
    {B,Len + L}.

encode_BMP_string(BMPString, TagIn) ->
    OctetList = mk_BMP_list(BMPString),
    encode_tags(TagIn, OctetList, length(OctetList)).

encode_UTF8_string(UTF8String, TagIn) when is_binary(UTF8String) ->
    encode_tags(TagIn, UTF8String, byte_size(UTF8String));
encode_UTF8_string(UTF8String, TagIn) ->
    encode_tags(TagIn, UTF8String, length(UTF8String)).

encode_boolean(true, TagIn) ->
    encode_tags(TagIn, [255], 1);
encode_boolean(false, TagIn) ->
    encode_tags(TagIn, [0], 1);
encode_boolean(X, _) ->
    exit({error,{asn1,{encode_boolean,X}}}).

encode_integer(Val) ->
    Bytes =
        if
            Val >= 0 ->
                encode_integer_pos(Val, []);
            true ->
                encode_integer_neg(Val, [])
        end,
    {Bytes,length(Bytes)}.

encode_integer(Val, Tag) when is_integer(Val) ->
    encode_tags(Tag, encode_integer(Val));
encode_integer(Val, _Tag) ->
    exit({error,{asn1,{encode_integer,Val}}}).

encode_integer_neg(- 1, [B1|_T] = L) when B1 > 127 ->
    L;
encode_integer_neg(N, Acc) ->
    encode_integer_neg(N bsr 8, [N band 255|Acc]).

encode_integer_pos(0, [B|_Acc] = L) when B < 128 ->
    L;
encode_integer_pos(N, Acc) ->
    encode_integer_pos(N bsr 8, [N band 255|Acc]).

encode_length(L) when L =< 127 ->
    {[L],1};
encode_length(L) ->
    Oct = minimum_octets(L),
    Len = length(Oct),
    if
        Len =< 126 ->
            {[128 bor Len|Oct],Len + 1};
        true ->
            exit({error,{asn1,too_long_length_oct,Len}})
    end.

encode_null(_Val, TagIn) ->
    encode_tags(TagIn, [], 0).

encode_object_identifier(Val, TagIn) ->
    encode_tags(TagIn, e_object_identifier(Val)).

encode_open_type(Val, T) when is_list(Val) ->
    encode_open_type(list_to_binary(Val), T);
encode_open_type(Val, Tag) ->
    encode_tags(Tag, Val, byte_size(Val)).

encode_restricted_string(OctetList, TagIn) when is_binary(OctetList) ->
    encode_tags(TagIn, OctetList, byte_size(OctetList));
encode_restricted_string(OctetList, TagIn) when is_list(OctetList) ->
    encode_tags(TagIn, OctetList, length(OctetList)).

encode_tags(TagIn, {BytesSoFar,LenSoFar}) ->
    encode_tags(TagIn, BytesSoFar, LenSoFar).

encode_tags([Tag|Trest], BytesSoFar, LenSoFar) ->
    {Bytes2,L2} = encode_length(LenSoFar),
    encode_tags(Trest,
                [Tag,Bytes2|BytesSoFar],
                LenSoFar + byte_size(Tag) + L2);
encode_tags([], BytesSoFar, LenSoFar) ->
    {BytesSoFar,LenSoFar}.

encode_unnamed_bit_string(Bits, TagIn) ->
    Unused = (8 - bit_size(Bits) band 7) band 7,
    Bin = <<Unused,Bits/bitstring,0:Unused>>,
    encode_tags(TagIn, Bin, byte_size(Bin)).

match_and_collect(Tlv, TagsIn) ->
    Val = match_tags(Tlv, TagsIn),
    case Val of
        [_|_] = PartList ->
            collect_parts(PartList);
        Bin when is_binary(Bin) ->
            Bin
    end.

match_tags({T,V}, [T]) ->
    V;
match_tags({T,V}, [T|Tt]) ->
    match_tags(V, Tt);
match_tags([{T,V}], [T|Tt]) ->
    match_tags(V, Tt);
match_tags([{T,_V}|_] = Vlist, [T]) ->
    Vlist;
match_tags(Tlv, []) ->
    Tlv;
match_tags({Tag,_V} = Tlv, [T|_Tt]) ->
    exit({error,{asn1,{wrong_tag,{{expected,T},{got,Tag,Tlv}}}}}).

minimum_octets(0, Acc) ->
    Acc;
minimum_octets(Val, Acc) ->
    minimum_octets(Val bsr 8, [Val band 255|Acc]).

minimum_octets(Val) ->
    minimum_octets(Val, []).

mk_BMP_list(In) ->
    mk_BMP_list(In, []).

mk_BMP_list([], List) ->
    lists:reverse(List);
mk_BMP_list([{0,0,C,D}|T], List) ->
    mk_BMP_list(T, [D,C|List]);
mk_BMP_list([H|T], List) ->
    mk_BMP_list(T, [H,0|List]).

mk_BMP_string(In) ->
    mk_BMP_string(In, []).

mk_BMP_string([], US) ->
    lists:reverse(US);
mk_BMP_string([0,B|T], US) ->
    mk_BMP_string(T, [B|US]);
mk_BMP_string([C,D|T], US) ->
    mk_BMP_string(T, [{0,0,C,D}|US]).

mk_object_val(0, Ack, Len) ->
    {Ack,Len};
mk_object_val(Val, Ack, Len) ->
    mk_object_val(Val bsr 7, [Val band 127 bor 128|Ack], Len + 1).

mk_object_val(Val) when Val =< 127 ->
    {[255 band Val],1};
mk_object_val(Val) ->
    mk_object_val(Val bsr 7, [Val band 127], 1).
