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
%%% @doc
%%% APNS wire-format encoding and decoding library.
%%%
%%% This supports the simple (0), enhanced (1), and "v2" (2) formats.
%%% @end
%%%-------------------------------------------------------------------
-module(apns_lib).

%%--------------------------------------------------------------------
%% API exports
%%--------------------------------------------------------------------
-export([
          encode_simple/2
        , encode_enhanced/4
        , encode_v2/5
        , decode/1
        , decode_error_packet/1
        , decode_feedback_packet/1
        , error_description/1
        , error_to_atom/1
        , maybe_encode_token/1
    ]).

%%--------------------------------------------------------------------
%% Defines
%%--------------------------------------------------------------------
-define(SIMPLE_CMD, 0).
-define(ENHANCED_CMD, 1).
-define(APNS_CMD_V2, 2).
-define(ERROR_PACKET_ID, 8).

-define(APNS_TOKEN_SIZE, 32). % This may change in future.

%% Command V2 item identities
-define(ID_TOKEN,    1).
-define(ID_PAYLOAD,  2).
-define(ID_NFN_ID,   3).
-define(ID_EXP_DATE, 4).
-define(ID_PRIORITY, 5).

-define(IS_INT_TYPE(Id), (Id =:= ?ID_NFN_ID orelse
                          Id =:= ?ID_EXP_DATE orelse
                          Id =:= ?ID_PRIORITY)).

-define(BYTE_1, 1).
-define(BYTE_4, 4).

-type apns_notification()     :: term().
-type apns_error()            :: term().
-type bytes()                 :: [byte()].
-type token()                 :: string() | bytes() | binary().
-type json()                  :: string() | binary().
-type apns_packet()           :: binary().
-type encode_error()          :: {error, encode_reason()}.
-type encode_reason()         :: bad_token | bad_json | payload_too_long.
-type decode_error()          :: {error, decode_reason()}.
-type decode_reason()         :: bad_packet | buffer_too_short | bad_json.
-type decode_err_pkt_error()  :: {error, decode_err_pkt_reason()}.
-type decode_err_pkt_reason() :: bad_packet.

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% @doc Encode `Token' and `Payload' into a "simple" (command 0) APNS
%% packet.
%% @end
%%--------------------------------------------------------------------
-spec encode_simple(Token, Payload) -> Result when
      Token :: token(), Payload :: json(),
      Result :: apns_packet() | encode_error().
encode_simple(<<Token/binary>>, <<Payload/binary>>) ->
    case encode_body(maybe_encode_token(Token), Payload) of
        <<Body/binary>> ->
            <<?SIMPLE_CMD, Body/binary>>;
        Error ->
            Error
    end;
encode_simple(Token, Payload) ->
    encode_simple(sc_util:to_bin(Token), sc_util:to_bin(Payload)).

%%--------------------------------------------------------------------
%% @doc Encode the `Id', `Expiry', `Token' and `Payload' into an
%% "enhanced" (command 1) APNS packet.
%% @end
%%--------------------------------------------------------------------
-spec encode_enhanced(Id, Expiry, Token, Payload) -> Result
    when Id :: integer(), Expiry :: integer(), Token :: token(),
         Payload :: json(), Result :: apns_packet() | encode_error().

encode_enhanced(Id, Expiry, <<Token/binary>>,
                <<Payload/binary>>) when is_integer(Id),
                                         is_integer(Expiry) ->
    case encode_body(maybe_encode_token(Token), Payload) of
        <<Body/binary>> ->
            <<?ENHANCED_CMD, Id:32, Expiry:32/big, Body/binary>>;
        Error ->
            Error
    end;
encode_enhanced(Id, Expiry, Token, Payload) ->
    encode_enhanced(Id, Expiry, sc_util:to_bin(Token), sc_util:to_bin(Payload)).

%%--------------------------------------------------------------------
%% @doc Encode into the command 3 APNS packet.
%% @end
%%--------------------------------------------------------------------
-spec encode_v2(Id, Expiry, Token, Payload, Prio) -> Result when
      Id :: integer(), Expiry :: integer(), Token :: token(),
      Payload :: json(), Prio :: integer(),
      Result :: apns_packet() | encode_error().
encode_v2(Id, Expiry, <<Token/binary>>, <<Payload/binary>>,
          Prio) when is_integer(Id) andalso
                     is_integer(Expiry) andalso
                     is_integer(Prio) andalso
                     0 =< Prio andalso Prio =< 255 ->
    make_v2_frame(
      [
       {?ID_NFN_ID,   Id},
       {?ID_EXP_DATE, Expiry},
       {?ID_TOKEN,    maybe_encode_token(Token)},
       {?ID_PAYLOAD,  Payload},
       {?ID_PRIORITY, Prio}
      ]
     );
encode_v2(Id, Expiry, Token, Payload, Prio) when is_integer(Id) andalso
                                                 is_integer(Expiry) andalso
                                                 is_integer(Prio) andalso
                                                 0 =< Prio andalso
                                                 Prio =< 255 ->
    encode_v2(Id, Expiry, sc_util:to_bin(Token),
              sc_util:to_bin(Payload), Prio).

%%--------------------------------------------------------------------
%% @doc Decode an encoded APNS packet.
%% @end
%%--------------------------------------------------------------------
-spec decode(Packet) -> Result when
      Packet :: binary(),
      Result :: apns_notification() | decode_error().
decode(<<?APNS_CMD_V2, Len:32, Body/binary>>) ->
    <<Items:Len/binary, Rest/binary>> = Body,
    case decode_v2_items(Items) of
        {error, _} = Error ->
            Error;
        R ->
            true = apns_recs:'#is_record-'(apns_notification, R),
            apns_recs:'#set-apns_notification'([{rest, Rest}], R)
    end;
decode(<<?ENHANCED_CMD, Id:32, Expire:32/big, Body/binary>>) ->
    case decode_body(Body) of
        {error, _} = Error ->
            Error;
        R ->
            true = apns_recs:'#is_record-'(apns_notification, R),
            apns_recs:'#set-apns_notification'([{cmd, enhanced},
                                                {id, Id},
                                                {expire, Expire}], R)
    end;
decode(<<?SIMPLE_CMD, Body/binary>> = _Packet) ->
    case decode_body(Body) of
        {error, _} = Error ->
            Error;
        R ->
            true = apns_recs:'#is_record-'(apns_notification, R),
            R
    end;
decode(<<_Other/binary>>) ->
    {error, bad_packet}.

%%--------------------------------------------------------------------
%% @doc Decode an error received from APNS.
%% @end
%%--------------------------------------------------------------------
-spec decode_error_packet(ErrPkt) -> Result when
      ErrPkt :: iolist() | binary(),
      Result :: apns_error() | decode_err_pkt_error().
decode_error_packet(ErrPkt) when is_list(ErrPkt); is_binary(ErrPkt) ->
    decode_error_packet_bin(sc_util:to_bin(ErrPkt)).

%%--------------------------------------------------------------------
%% @doc Decode a feedback packet received from APNS feedback service.
%% @end
%%--------------------------------------------------------------------
-type decoded_packet() :: {Timestamp :: integer(),
                           Token :: binary()}.
-spec decode_feedback_packet(Packet) -> Result when
      Packet :: list() | binary(), Result :: [decoded_packet()].
decode_feedback_packet(Packet) when is_list(Packet) ->
    decode_feedback_packet(list_to_binary(Packet));
decode_feedback_packet(<<Packet/binary>>) ->
    decode_feedback_packet(<<Packet/binary>>, []).

-spec decode_feedback_packet(Packet, Acc) -> Result when
      Packet :: binary(), Acc :: [decoded_packet()],
      Result :: [decoded_packet()].
decode_feedback_packet(<<Timestamp:32/big-integer,
                         TokenLen:16/big-integer,
                         Rest/binary>>,
                       Acc) ->
    case Rest of
        <<Token:TokenLen/binary, More/binary>> ->
            decode_feedback_packet(More, [{Timestamp, Token} | Acc]);
        <<Packet/binary>> ->
            error_logger:error_report([
                    {module, ?MODULE},
                    {pid, self()},
                    {packet_too_short, Packet}
                ]),
            decode_feedback_packet(<<>>, Acc)
    end;
decode_feedback_packet(<<>>, Acc) ->
    lists:reverse(Acc);
decode_feedback_packet(<<Packet/binary>>, Acc) ->
    error_logger:error_report([
            {module, ?MODULE},
            {pid, self()},
            {packet_too_short, Packet}
        ]),
    decode_feedback_packet(<<>>, Acc).

%%--------------------------------------------------------------------
%% @doc Convert APNS error code to textual description (as binary
%% string).
%% @end
%%--------------------------------------------------------------------
-spec error_description(Err) -> Desc when
      Err :: integer(), Desc :: binary().

error_description(0)   -> <<"No errors encountered">>;
error_description(1)   -> <<"Processing error">>;
error_description(2)   -> <<"Missing device token">>;
error_description(3)   -> <<"Missing topic">>;
error_description(4)   -> <<"Missing payload">>;
error_description(5)   -> <<"Invalid token size">>;
error_description(6)   -> <<"Invalid topic size">>;
error_description(7)   -> <<"Invalid payload size">>;
error_description(8)   -> <<"Invalid token">>;
error_description(10)  -> <<"Shutdown">>;
error_description(255) -> <<"None (unknown)">>;

error_description(N) when is_integer(N) ->
    list_to_binary([<<"Error ">>, integer_to_list(N)]).

%%--------------------------------------------------------------------
%% @doc Convert APNS error code to symbolic name (an atom).
%% @end
%%--------------------------------------------------------------------
-spec error_to_atom(Err) -> Atom when
      Err :: 0..255, Atom :: atom().
error_to_atom(0)   -> ok;
error_to_atom(1)   -> processing_error;
error_to_atom(2)   -> missing_device_token;
error_to_atom(3)   -> missing_topic;
error_to_atom(4)   -> missing_payload;
error_to_atom(5)   -> invalid_token_size;
error_to_atom(6)   -> invalid_topic_size;
error_to_atom(7)   -> invalid_payload_size;
error_to_atom(8)   -> invalid_token;
error_to_atom(10)  -> shutdown;
error_to_atom(255) -> unknown;
error_to_atom(N) when is_integer(N) ->
    list_to_atom("error_" ++ integer_to_list(N)).

%%--------------------------------------------------------------------
%% @doc Convert APNSv2 field ID to `apns_notification' record field name
%% or false if ID is unknown.
%% @end
%%--------------------------------------------------------------------
id_to_atom(?ID_TOKEN)    -> token;
id_to_atom(?ID_PAYLOAD)  -> payload;
id_to_atom(?ID_NFN_ID)   -> id;
id_to_atom(?ID_EXP_DATE) -> expire;
id_to_atom(?ID_PRIORITY) -> priority;
id_to_atom(_Unknown    ) -> undefined.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------
encode_body(<<Token/binary>>, <<Json/binary>>) ->
    <<(byte_size(Token)):16/big, Token/binary,
      (byte_size(Json)):16/big, Json/binary>>.

decode_body(<<TokLen:16/big, Rest/binary>>) ->
    case Rest of
        <<Token:TokLen/binary, PayloadLen:16/big, PayloadAndRest/binary>> ->
            decode_payload(Token, PayloadLen, PayloadAndRest);
        <<_/binary>> ->
            {error, buffer_too_short}
    end.

decode_payload(Token, PayloadLen, <<PayloadAndRest/binary>>) ->
    case PayloadAndRest of
        <<Payload:PayloadLen/binary, Rest/binary>> ->
            create_notification(Token, Payload, Rest);
        <<_/binary>> ->
            {error, buffer_too_short}
    end.

decode_v2_items(<<Items/binary>>) ->
    case decode_v2_items(Items, []) of
        [_|_] = L ->
            apns_notification_v2(L);
        Error ->
            Error
    end.

decode_v2_items(<<Id, Len:16, Data/binary>>, Acc) ->
    case Data of
        <<Item:Len/binary, Rest/binary>> ->
            decode_v2_items(Rest, [decode_item(Id, Len, Item) | Acc]);
        <<_/binary>> ->
            {error, buffer_too_short}
    end;
decode_v2_items(<<>>, Acc) ->
    lists:reverse(Acc);
decode_v2_items(<<_/binary>>, _Acc) ->
    {error, buffer_too_short}.

apns_notification_v2(L) ->
    Props = [{Attr, V} || {Id, V} <- L, begin Attr = id_to_atom(Id),
                                              Attr /= undefined
                                        end],
    apns_recs:'#new-apns_notification'([{cmd, v2} | Props]).

decode_item(Id, Len, <<Item/binary>>) ->
    (item_decoder(Id))(Id, Len, Item).

item_decoder(Id) when ?IS_INT_TYPE(Id) ->
    fun decode_item_int/3;
item_decoder(_) ->
    fun decode_item_binary/3.

decode_item_int(Id, Len, <<B/binary>>) ->
    <<Int:Len/big-integer-unit:8>> = B,
    {Id, Int}.

decode_item_binary(Id, Len, <<B/binary>>) ->
    <<Item:Len/binary>> = B,
    {Id, Item}.

create_notification(Token, Payload, Rest) ->
    apns_recs:'#new-apns_notification'([{token, Token},
                                        {payload, Payload},
                                        {rest, Rest}]).

-spec decode_error_packet_bin(ErrPkt) -> Result when
      ErrPkt :: binary(),
      Result :: apns_error() | decode_err_pkt_error().
decode_error_packet_bin(<<?ERROR_PACKET_ID, Status, Id:32>>) ->
    make_apns_error(Id, Status);
decode_error_packet_bin(<<_/binary>>) ->
    {error, bad_packet}.

-spec make_apns_error(Id, Status) -> ApnsError
    when Id :: integer(), Status :: integer(), ApnsError:: apns_error().
make_apns_error(Id, Status) ->
    apns_recs:'#new-apns_error'([{id, Id},
                                 {status, error_to_atom(Status)},
                                 {status_code, Status},
                                 {status_desc, error_description(Status)}]).

%% The token may have been passed in unconverted hex string format,
%% while APNS expects it to be in binary. If it's an Erlang binary,
%% check if the token size is the expected one (currently 32 bytes)
%% or not. If not, convert it to list format try to encode it
%% to binary from what hopefully is a hex string.
%%
%% If that works, it's *probably* a token, so return
%% the resulting binary. If it fails, return the original binary and
%% assume it's really a token (APNS will definitely reject it if it is wrong).
maybe_encode_token(<<B/binary>>) when byte_size(B) == ?APNS_TOKEN_SIZE ->
    B;
maybe_encode_token(<<B/binary>>) ->
    try maybe_encode_token(binary_to_list(B)) of
        Token when byte_size(Token) == ?APNS_TOKEN_SIZE ->
            Token;
        _ -> % Just use the original, even if "wrong" size - future-proofing?
            B
    catch
        _:_ -> % Can't convert to list, leave as original
            B
    end;
maybe_encode_token([_|_] = L) ->
    sc_util:hex_to_bitstring(L).

%%--------------------------------------------------------------------
%% Command 3 functions
%%--------------------------------------------------------------------
make_v2_frame([{_Id, _Val}|_] = Items) ->
    SI = lists:keysort(1, Items),
    BItems = << <<(make_item(Id, Val))/binary>> || {Id, Val} <- SI >>,
    <<?APNS_CMD_V2, (byte_size(BItems)):32, BItems/binary>>.

-compile({inline, [{make_item, 2}]}).

make_item(Id, <<B/binary>>) when Id =:= ?ID_TOKEN; Id =:= ?ID_PAYLOAD ->
    make_bin_item(Id, B);
make_item(Id, Int) when is_integer(Int) andalso
                        Id =:= ?ID_NFN_ID orelse Id =:= ?ID_EXP_DATE ->
    make_int_item(Id, Int, ?BYTE_4);
make_item(Id, Int) when is_integer(Int), Id =:= ?ID_PRIORITY ->
    make_int_item(Id, Int, ?BYTE_1).

-compile({inline, [{make_bin_item, 2}, {make_int_item, 3}]}).

make_bin_item(Id, <<Item/binary>>) ->
    <<Id, (byte_size(Item)):16, Item/bytes>>.

make_int_item(Id, Int, ByteLen) ->
    <<Id, ByteLen:16, Int:ByteLen/big-integer-unit:8>>.

