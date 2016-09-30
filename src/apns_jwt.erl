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
%%% @doc This module creates a JWT suitable for use with APNS.
%%% @end
%%%-------------------------------------------------------------------
-module(apns_jwt).

-export([jwt/3]).

-export_type([
              alg/0,
              base64_urlencoded/0,
              bstring/0,
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
              posix_time/0
             ]).

-include_lib("public_key/include/public_key.hrl").

-define(JWT_ALG, <<"ES256">>).

%%%-------------------------------------------------------------------
%%% Types
%%%-------------------------------------------------------------------
-type bstring() :: binary().
-type base64_urlencoded() :: bstring().
-type json() :: bstring().
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
%%   <dd>`SigningKey :: binary()'</dd>
%%   <dt>This is the PEM-encoded private key downloaded from the Apple
%%   developer portal.</dt>
%% </dl>
%% @end
%%-------------------------------------------------------------------
-spec jwt(KID, Issuer, SigningKey) -> JWT when
      KID :: kid(), Issuer :: iss(), SigningKey :: pem_encoded_key(),
      JWT :: jwt().
jwt(KID, Issuer, SigningKey) when is_binary(KID),
                                  is_binary(Issuer),
                                  is_binary(SigningKey) ->
    SigningInput = signing_input(KID, Issuer),
    Signature = signature(SigningInput, SigningKey),
    list_to_binary([SigningInput, $., Signature]).

%%%====================================================================
%%% Internal
%%%====================================================================
-spec signing_input(KID, Issuer) -> Result when
      KID :: kid(), Issuer :: iss(), Result :: jws_signing_input().
signing_input(KID, Issuer) when is_binary(KID), is_binary(Issuer) ->
    list_to_binary([base64urlencode(header(KID)), $.,
                    base64urlencode(payload(Issuer))]).

%%--------------------------------------------------------------------
-spec signature(SigningInput, SigningKey) -> Result when
      SigningInput :: jws_signing_input(), SigningKey :: pem_encoded_key(),
      Result :: jws_signature().
signature(SigningInput, SigningKey) when is_binary(SigningInput),
                                         is_binary(SigningKey) ->
    [PemEntry] = public_key:pem_decode(SigningKey),
    PemKey = public_key:pem_entry_decode(PemEntry),
    PrivKey = [PemKey#'PrivateKeyInfo'.privateKey, prime256v1],
    base64urlencode(crypto:sign(ecdsa, sha256, SigningInput, PrivKey)).

%%--------------------------------------------------------------------
-spec base64urlencode(Bin) -> Result when
      Bin :: binary(), Result :: base64_urlencoded().
base64urlencode(<<Bin/binary>>) ->
    << << case Byte of $+ -> $-; $/ -> $_; _ -> Byte end >>
       || <<Byte>> <= base64:encode(Bin), Byte =/= $= >>.

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
    jsx:encode([{alg, Alg}, {kid, KeyId}]).

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
