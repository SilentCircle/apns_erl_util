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
%%% @doc APNS HTTP/2 support library.
%%% This is the next format after the v2 binary format, v3 if you like.
%%% See [https://developer.apple.com] for more information.
%%% @end
-module(apns_lib_http2).

-include_lib("public_key/include/public_key.hrl").

-export([
          host_port/1
        , make_req/3
        , make_req_hdrs/4
        , make_ssl_opts/2
        , make_uuid/0
        , parse_resp/1
        , parse_resp_body/1
        , reason_desc/1
        , status_desc/1
        ]).

-export_type([
                bstring/0
              , http2_hdrs/0
              , http2_hdr/0
              , http2_req_body/0
              , http2_req/0
              , http2_rsp_body/0
              , http2_rsp/0
              , parsed_rsp/0
              , parsed_rsp_val/0
              , req_opt/0
              , req_opts/0
              , uuid_str/0
             ]).

%%--------------------------------------------------------------------
%% Types
%%--------------------------------------------------------------------
-type bstring()        :: binary().
-type http2_hdr()      :: {Key :: bstring(), Val :: bstring()}.
-type http2_hdrs()     :: [http2_hdr()].
-type http2_req_body() :: bstring().
-type http2_req()      :: {http2_hdrs(), http2_req_body()}.
-type http2_rsp_body() :: undefined | [bstring()].
-type http2_rsp()      :: {http2_hdrs(), http2_rsp_body()}.
-type uuid_str()       :: bstring().
-type parsed_rsp_val() :: {uuid, uuid_str()}
                        | {status, bstring()}
                        | {status_desc, bstring()}
                        | {reason, bstring()}
                        | {reason_desc, bstring()}
                        | {timestamp, non_neg_integer() | undefined}
                        | {timestamp_desc, bstring() | undefined}
                        | {body, term()}.

-type parsed_rsp()     :: [parsed_rsp_val()].
-type req_opt()        :: {uuid, uuid_str()}
                        | {topic, bstring()}
                        | {expiration, non_neg_integer()}
                        | {priority, non_neg_integer()}.

-type req_opts()       :: [req_opt()].

%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

%%--------------------------------------------------------------------
%% @doc Create an HTTP/2 request ready to send.
%%
%% <dl>
%% <dt>`Token'</dt>
%%    <dd>The APNS token as a hexadecimal binary string.</dd>
%% <dt>`JSON'</dt>
%%    <dd>The formatted JSON payload as a binary string.</dd>
%% <dt>`Opts'</dt>
%%    <dd>A proplist containing one or more of the following:
%%      <ul>
%%        <li>`{uuid, uuid_str()}': A canonical UUID that identifies the
%%        notification. If there is an error sending the notification, APNs
%%        uses this value to identify the notification to your server.  The
%%        canonical form is 32 lowercase hexadecimal digits, displayed in five
%%        groups separated by hyphens in the form 8-4-4-4-12. An example UUID
%%        is as follows: `123e4567-e89b-12d3-a456-42665544000'. If you omit
%%        this header, a new UUID is created by APNs and returned in the
%%        response.</li>
%%
%%        <li>`{topic, string | bstring()}': The topic of the remote
%%        notification, which is typically the bundle ID for your app. The
%%        certificate you create in Member Center must include the capability
%%        for this topic.  If your certificate includes multiple topics, you
%%        must specify a value for this header.  If you omit this header and
%%        your APNs certificate does not specify multiple topics, the APNs
%%        server uses the certificate’s Subject as the default topic.</li>
%%
%%        <li>`{priority, non_neg_integer()}': The priority of the notification.
%%        Specify one of the following values:
%%          <ul>
%%            <li>`10'–Send the push message immediately. Notifications with this
%%            priority must trigger an alert, sound, or badge on the target
%%            device. It is an error to use this priority for a push notification
%%            that contains only the content-available key.</li>
%%            <li>`5'—Send the push message at a time that takes into account
%%            power considerations for the device. Notifications with this
%%            priority might be grouped and delivered in bursts. They are
%%            throttled, and in some cases are not delivered.  If you omit this
%%            header, the APNs server sets the priority to `10'.</li>
%%          </ul>
%%        </li>
%%        <li>`{expiration, non_neg_integer()}': A UNIX epoch date expressed in
%%        seconds (UTC). This header identifies the date when the notification is
%%        no longer valid and can be discarded.  If this value is nonzero, APNs
%%        stores the notification and tries to deliver it at least once,
%%        repeating the attempt as needed if it is unable to deliver the
%%        notification the first time. If the value is `0', APNs treats the
%%        notification as if it expires immediately and does not store the
%%        notification or attempt to redeliver it.</li>
%%      </ul>
%%    </dd>
%% <dt>`APNSId'</dt>
%%    <dd>A unique id for this request</dd>
%% </dl>
%%
%% Returns `{http2_hdrs(), http2_req_body()}'.
%% @see apns_json
%% @end
%%--------------------------------------------------------------------
-spec make_req(Token, JSON, Opts) -> Req
    when Token :: string() | bstring(), JSON :: string() | bstring(),
         Opts :: req_opts(), Req :: http2_req().
make_req(Token, JSON, Opts) when is_list(Opts) ->
    HTTPPath = b([<<"/3/device/">>, b(Token)]),
    ReqHdrs = make_req_hdrs(<<"POST">>, HTTPPath, <<"https">>, Opts),
    ReqBody = b(JSON),
    {ReqHdrs, ReqBody}.

%%--------------------------------------------------------------------
%% make_req_hdrs/4
%%--------------------------------------------------------------------
-spec make_req_hdrs(Method, Path, Scheme, Opts) -> Headers
    when Method :: string() | bstring(), Path :: string() | bstring(),
         Scheme :: string() | bstring(), Opts :: req_opts(),
         Headers :: http2_hdrs().
make_req_hdrs(Method, Path, Scheme, Opts) when is_list(Opts) ->
    [{<<":method">>, b(Method)},
     {<<":path">>, b(Path)},
     {<<":scheme">>, b(Scheme)}] ++ apns_opts(Opts).

%%--------------------------------------------------------------------
%% @doc Make a UUID suitable for APNS id header.
%%
%% The return value is a binary string comprising 32 lowercase hexadecimal
%% digits, displayed in five groups separated by hyphens in the form
%% 8-4-4-4-12.
%%
%% == Example ==
%%
%% ```
%% >make_uuid().
%% <<"123e4567-e89b-12d3-a456-42665544000">>
%% '''
%%
%% @end
%%--------------------------------------------------------------------
-spec make_uuid() -> uuid_str().
make_uuid() ->
    b(uuid:uuid_to_string(uuid:get_v4())).

%%--------------------------------------------------------------------
%% @doc Parse HTTP/2 response body and headers.
%% Return proplist with parsed body, uuid, status, and other information.
%% @end
%%--------------------------------------------------------------------
-spec parse_resp(Resp) -> Result
    when Resp :: http2_rsp(), Result :: parsed_rsp().
parse_resp({RespHdrs, RespBody}) ->
    Id = sc_util:req_val(<<"apns-id">>, RespHdrs),
    S = sc_util:req_val(<<":status">>, RespHdrs),
    SD = status_desc(S),
    OptProps = case parse_resp_body(RespBody) of
                   [] ->
                       [];
                   [{Reason, EJSON}] ->
                       [{reason, Reason},
                        {reason_desc, reason_desc(Reason)},
                        {body, EJSON}];
                   [{Reason, TS, EJSON}] ->
                       [{reason, Reason},
                        {reason_desc, reason_desc(Reason)},
                        {timestamp, TS},
                        {timestamp_desc, timestamp_desc(TS)},
                        {body, EJSON}]
               end,

    [{uuid, Id}, {status, S}, {status_desc, SD} | OptProps].

%%--------------------------------------------------------------------
%% @doc Parse APNS HTTP/2 response body.
%% @end
%%--------------------------------------------------------------------
-spec parse_resp_body(RespBody) -> Result
    when RespBody :: http2_rsp_body(), Reason :: bstring(),
         Timestamp :: undefined | non_neg_integer(),
         EJSON :: apns_json:json_term(),
         Result :: [] | [{Reason, EJSON}] | [{Reason, Timestamp, EJSON}].
parse_resp_body([]) ->
    [];
parse_resp_body([<<RespBody/bytes>>]) ->
    EJSON = jsx:decode(RespBody),
    Reason = sc_util:req_val(<<"reason">>, EJSON),
    Result = case sc_util:val(<<"timestamp">>, EJSON) of
                 undefined ->
                     {Reason, EJSON};
                 TS when is_integer(TS) ->
                     {Reason, TS, EJSON}
             end,
    [Result];
parse_resp_body(undefined) ->
    [].

%%--------------------------------------------------------------------
%% @doc Map HTTP/2 status code to textual description.
%% @end
%%--------------------------------------------------------------------
-spec status_desc(Status) -> Desc
    when Status :: bstring(), Desc :: bstring().
status_desc(<<"200">>) ->
    <<"Success">>;
status_desc(<<"400">>) ->
    <<"Bad request">>;
status_desc(<<"403">>) ->
    <<"There was an error with the certificate.">>;
status_desc(<<"405">>) ->
    <<
      "The request used a bad :method value. Only POST requests are "
      "supported."
    >>;
status_desc(<<"410">>) ->
    <<"The device token is no longer active for the topic.">>;
status_desc(<<"413">>) ->
    <<"The notification payload was too large.">>;
status_desc(<<"429">>) ->
    <<"The server received too many requests for the same device token.">>;
status_desc(<<"500">>) ->
    <<"Internal server error">>;
status_desc(<<"503">>) ->
    <<"The server is shutting down and unavailable.">>;
status_desc(<<B/bytes>>) ->
    list_to_binary([<<"Unknown status ">>, B]).

%%--------------------------------------------------------------------
%% @doc Map APNS HTTP/2 reason to text description.
%% @end
%%--------------------------------------------------------------------
-spec reason_desc(Reason) -> Desc
    when Reason :: bstring(), Desc :: bstring().
reason_desc(<<"PayloadEmpty">>) ->
    <<"The message payload was empty.">>;
reason_desc(<<"PayloadTooLarge">>) ->
    <<"The message payload was too large. The maximum payload size is 4096 "
      "bytes.">>;
reason_desc(<<"BadTopic">>) ->
    <<"The apns-topic was invalid.">>;
reason_desc(<<"TopicDisallowed">>) ->
    <<"Pushing to this topic is not allowed.">>;
reason_desc(<<"BadMessageId">>) ->
    <<"The apns-id value is bad.">>;
reason_desc(<<"BadExpirationDate">>) ->
    <<"The apns-expiration value is bad.">>;
reason_desc(<<"BadPriority">>) ->
    <<"The apns-priority value is bad.">>;
reason_desc(<<"MissingDeviceToken">>) ->
    <<"The device token is not specified in the request :path. Verify that "
      "the :path header contains the device token.">>;
reason_desc(<<"BadDeviceToken">>) ->
    <<
      "The specified device token was bad. Verify that the request contains "
      "a valid token and that the token matches the environment."
    >>;
reason_desc(<<"DeviceTokenNotForTopic">>) ->
    <<"The device token does not match the specified topic.">>;
reason_desc(<<"Unregistered">>) ->
    <<"The device token is inactive for the specified topic.">>;
reason_desc(<<"DuplicateHeaders">>) ->
    <<"One or more headers were repeated.">>;
reason_desc(<<"BadCertificateEnvironment">>) ->
    <<"The client certificate was for the wrong environment.">>;
reason_desc(<<"BadCertificate">>) ->
    <<"The certificate was bad.">>;
reason_desc(<<"Forbidden">>) ->
    <<"The specified action is not allowed.">>;
reason_desc(<<"BadPath">>) ->
    <<"The request contained a bad :path value.">>;
reason_desc(<<"MethodNotAllowed">>) ->
    <<"The specified :method was not POST.">>;
reason_desc(<<"TooManyRequests">>) ->
    <<"Too many requests were made consecutively to the same device token.">>;
reason_desc(<<"IdleTimeout">>) ->
    <<"Idle time out.">>;
reason_desc(<<"Shutdown">>) ->
    <<"The server is shutting down.">>;
reason_desc(<<"InternalServerError">>) ->
    <<"An internal server error occurred.">>;
reason_desc(<<"ServiceUnavailable">>) ->
    <<"The service is unavailable.">>;
reason_desc(<<"MissingTopic">>) ->
    <<
      "The apns-topic header of the request was not specified and was "
      "required. The apns-topic header is mandatory when the client is "
      "connected using a certificate that supports multiple topics."
    >>;
reason_desc(<<Other/bytes>>) ->
    Other.

%%--------------------------------------------------------------------
%% @doc Return default SSL options for APNS HTTP/2.
%% @end
%%--------------------------------------------------------------------
-spec make_ssl_opts(CertFile, KeyFile) -> Opts
    when CertFile :: string(), KeyFile :: string(),
         Opts :: [{atom(), term()}].
make_ssl_opts(CertFile, KeyFile) ->
    [{certfile, CertFile},
     {keyfile, KeyFile},
     {honor_cipher_order, false},
     {versions, ['tlsv1.2']},
     {alpn_preferred_protocols, [<<"h2">>]}].

%%--------------------------------------------------------------------
%% @doc Returns a default `{Host, Port}' for `prod' or `dev' APNS environment.
%% @end
%%--------------------------------------------------------------------
-spec host_port(Env) -> HostPort
    when Env :: prod | dev, HostPort :: {Host, Port},
         Host :: string(), Port :: non_neg_integer().
host_port(prod) -> {"api.push.apple.com", 443};
host_port(dev)  -> {"api.development.push.apple.com", 443}.

%%%-------------------------------------------------------------------
%%% Internal Functions
%%%-------------------------------------------------------------------

%%--------------------------------------------------------------------
-spec apns_opts(Opts) -> Headers
    when Opts :: req_opts(), Headers :: http2_hdrs().
apns_opts(Opts) ->
    lists:foldl(
      fun({uuid, V}, Acc)       -> [{<<"apns-id">>, b(V)} | Acc];
         ({topic, V}, Acc)      -> [{<<"apns-topic">>, b(V)} | Acc];
         ({expiration, V}, Acc) -> [{<<"apns-expiration">>, b(V)} | Acc];
         ({priority, V}, Acc)   -> [{<<"apns-priority">>, b(V)} | Acc];
         (Unsupp, _Acc)         -> throw({unsupported_apns_opt, Unsupp})
      end, [], Opts).


%% Timestamp is POSIX time in milliseconds
%% [<<"{\"reason\":\"Unregistered\",\"timestamp\":1468938386863}">>]

%%--------------------------------------------------------------------
-spec timestamp_desc(TS) -> Desc
    when TS :: non_neg_integer() | undefined,
         Desc :: bstring() | undefined.
timestamp_desc(undefined) ->
    undefined;
timestamp_desc(TS) when is_integer(TS), TS > 0 ->
    b(posix_ms_to_iso8601(TS)).

-compile({inline, [{b, 1}]}).
b(X) -> sc_util:to_bin(X).

-compile({inline, [{posix_ms_to_iso8601, 1}]}).
posix_ms_to_iso8601(TS) ->
    now_to_iso8601(posix_ms_to_timestamp(TS)).

-compile({inline, [{posix_ms_to_timestamp, 1}]}).
posix_ms_to_timestamp(TS) when is_integer(TS), TS >= 0 ->
    {TS div 1000000000, TS rem 1000000000 div 1000, TS rem 1000 * 1000}.

now_to_iso8601(Now) ->
    {{Y,Mo,D},{H,M,S}} = calendar:now_to_universal_time(Now),
    io_lib:format("~B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ",
                  [Y, Mo, D, H, M, S]).
