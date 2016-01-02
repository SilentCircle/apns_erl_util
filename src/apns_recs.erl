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
%%% @doc `apns_recs' provides exported records (exprecs) to avoid record
%%% coupling by external users of these records.  This exports the following
%%% general functions:
%%%
%%% ```
%%%'#exported_records-'/0        '#is_record-'/2
%%%'#fromlist-'/2                '#new-'/1
%%%'#fromlist-apns_error'/1      '#new-apns_error'/0
%%%'#fromlist-apns_error'/2      '#new-apns_error'/1
%%%'#get-'/2                     '#pos-'/2
%%%'#get-apns_error'/2           '#pos-apns_error'/1
%%%'#info-'/1                    '#set-'/2
%%%'#info-'/2                    '#set-apns_error'/2
%%%'#info-apns_error'/1          module_info/0
%%%'#is_record-'/1               module_info/1
%%% '''
%%%
%%% ## apns_error record functions
%%% ```
%%%'#fromlist-apns_error'/1      '#new-apns_error'/0
%%%'#fromlist-apns_error'/2      '#new-apns_error'/1
%%%'#get-apns_error'/2           '#pos-apns_error'/1
%%%'#info-apns_error'/1'         '#set-apns_error'/2
%%% '''
%%%
%%% Compiling this module requires the `exprecs' parse transform from
%%% uwiger/parse_transform on github.
%%% @end
%%%====================================================================
-module(apns_recs).
-compile({parse_transform, exprecs}).

-include("apns_recs.hrl").

-export_records([apns_notification, apns_error]).
