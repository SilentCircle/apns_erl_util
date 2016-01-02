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
%%% @copyright (C) 2015 Silent Circle LLC
%%% @doc Types used in this library.
%%% @end
%%%====================================================================
-ifndef(__APNS_TYPES_HRL).
-define(__APNS_TYPES_HRL, true).

%%--------------------------------------------------------------------
%% Types
%%--------------------------------------------------------------------
-type hexdigits()             :: string().
-type bytes()                 :: [byte()].
-type token()                 :: string() | bytes() | binary().
-type json()                  :: string() | binary().
-type cmd_type()              :: simple | enhanced | v2.
-type apns_packet()           :: binary().
-type encode_error()          :: {error, encode_reason()}.
-type encode_reason()         :: bad_token | bad_json | payload_too_long.
-type decode_error()          :: {error, decode_reason()}.
-type decode_reason()         :: bad_packet | buffer_too_short | bad_json.
-type decode_err_pkt_error()  :: {error, decode_err_pkt_reason()}.
-type decode_err_pkt_reason() :: bad_packet.

-endif.
