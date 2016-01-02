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
%%% APNS JSON notification creation library.
%%% @end
%%%-------------------------------------------------------------------
-module(apns_json).
-export([make_notification/1]).

%%--------------------------------------------------------------------
%% @doc Create a notification consisting of a JSON binary suitable for
%% transmitting to the Apple Push Service.
%%
%% Details on the notification proplist's properties follow.
%%
%%
%% === Notification Properties ===
%%
%%
%% <dl>
%%   <dt>`alert'</dt>
%%      <dd>Binary or proplist. If a binary, it will be used
%%      as the notification text. If a proplist, see below for
%%      format of the proplist.</dd>
%%   <dt>`badge'</dt>
%%      <dd>Badge count (integer)</dd>
%%   <dt>`sound'</dt>
%%      <dd>Name of sound file in app bundle to play.</dd>
%%   <dt>`extra'</dt>
%%      <dd>Additional (optional) custom data, which must be an
%%          object (Erlang proplist) as described in the table below.
%%
%%      <table class="with-borders">
%%        <tr>
%%          <th><strong>json</strong></th><th><strong>erlang</strong></th>
%%        </tr>
%%        <tr>
%%          <td> <code>number</code> </td>
%%          <td> <code>integer()</code> and <code>float()</code></td>
%%        </tr>
%%        <tr>
%%          <td> <code>string</code> </td>
%%          <td> <code>binary()</code> </td>
%%        </tr>
%%        <tr>
%%          <td> <code>true</code>, <code>false</code> and <code>null</code></td>
%%          <td> <code>true</code>, <code>false</code> and <code>null</code></td>
%%        </tr>
%%        <tr>
%%          <td> <code>array</code> </td>
%%          <td> <code>[]</code> and <code>[JSON]</code></td>
%%        </tr>
%%        <tr>
%%          <td> <code>object</code> </td>
%%          <td> <code>[{}]</code> and <code>[{binary() OR atom(), JSON}]</code></td>
%%        </tr>
%%      </table>
%%      </dd>
%% </dl>
%%
%%
%% === Alert Properties ===
%%
%%
%% This describes the proplist that is expected if ``'alert''' is not a
%% binary string (e.g. `<<"This is a message.">>').
%% <dl>
%%   <dt>`body'</dt><dd>The alert text to be displayed (binary)</dd>
%%   <dt>``'action-loc-key'''</dt>
%%      <dd>
%%       If a string is specified, displays an alert with two buttons.
%%       However, iOS uses the string as a key to get a localized string in the
%%       current localization to use for the right button's title instead of
%%       "View". If the value is `null', the system displays an alert with a
%%       single OK button that simply dismisses the alert when tapped. See
%%       <a href="https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW21">Localized Formatted Strings</a>
%%       for more information.
%%      </dd>
%%   <dt>``'loc-key'''</dt>
%%     <dd>
%%      A key to an alert-message string in a Localizable.strings file for
%%      the current localization (which is set by the user's language
%%      preference). The key string can be formatted with `%@' and `%n$@'
%%      specifiers to take the variables specified in ``'loc-args'''.
%%     </dd>
%%   <dt>``'loc-args'''</dt>
%%     <dd>
%%      This array of binaries contains variable values to be substituted into
%%      the format string defined in ``'loc-key'''.
%%     </dd>
%%   <dt>``'launch-image'''</dt>
%%     <dd>
%%      The filename of an image file in the application bundle; it may include
%%      the extension or omit it. The image is used as the launch image when
%%      users tap the action button or move the action slider. If this property
%%      is not specified, the system either uses the previous snapshot, uses the
%%      image identified by the `UILaunchImageFile' key in the application's
%%      `Info.plist' file, or falls back to `Default.png'.
%%     </dd>
%% </dl>
%%
%% == Examples of Notification proplist ==
%%
%% === Simplest Possible Alert ===
%%
%% ```
%% Notification = [
%%     {'alert', <<"Would you like to play a game?">>}
%% ].
%% '''
%%
%% === Alert with sound and badge ===
%%
%% ```
%% Notification = [
%%     {'alert', <<"Would you like to play a game?">>},
%%     {'badge', 1},
%%     {'sound', <<"wopr">>}
%% ].
%% '''
%%
%% === Alert with additional custom JSON data ===
%%
%% ```
%% Notification = [
%%     {'alert', <<"Would you like to play a game?">>},
%%     {'extra', [{<<"meta">>, [{<<"movie">>, <<"War Games">>}]]}
%% ].
%% '''
%%
%% === Localized alert using 'loc-key' and 'loc-args' ===
%%
%% ```
%% Notification = [
%%     {'alert',
%%         [
%%             {'loc-key', <<"GAME_PLAY_REQUEST_FORMAT">>},
%%             {'loc-args', [<<"Jenna">>, <<"Frank">>]}
%%         ]
%%     },
%%     {'sound', <<"chime">>}
%% ].
%% '''
%%
%% == More Information ==
%%
%% For information on the keys in the proplist, see
%% <a href="https://developer.apple.com/library/ios/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/">
%% Local and Push Notification Programming Guide
%% </a> (requires Apple Developer login).
%%
%% @end
%%--------------------------------------------------------------------
-spec make_notification(PL) -> ApnsJsonNotification when
      PL :: [proplists:property()],
      ApnsJsonNotification :: binary().
make_notification(PL) ->
    Alert = sc_util:val(alert, PL, <<>>),
    Badge = sc_util:val(badge, PL),
    Sound = sc_util:to_bin(sc_util:val(sound, PL, <<>>)),
    %% Extra is an optional user-defined proplist in jsx-decoded
    %% format, which gets inserted at the top level of the resulting
    %% JSON
    Extra = sc_util:val(extra, PL, []),

    Body = make_alert(Alert) ++
           [{<<"content-available">>, 1}] ++ % SCPF-25: Enable push in backgrounded app
           optional(<<"badge">>, Badge) ++
           optional(<<"sound">>, Sound),

    jsx:encode([{<<"aps">>, Body}] ++ Extra).

%%--------------------------------------------------------------------
%% @doc Rearrange `AlertPL' into a JSON APNS-ready alert proplist. Note that
%% `AlertPL' must contain at least one {key, value} property. A JSON APNS-ready
%% proplist is one in which all property keys are string binaries, and the
%% proplist is organized according to the APNS documentation.
%% @end
%%--------------------------------------------------------------------
-type alert_proplist() :: [proplists:property(),...].
-type alert() :: alert_proplist() | binary() | string().

-spec make_alert(Alert) -> JsonReadyProplist when
      Alert:: alert(),
      JsonReadyProplist :: [proplists:property()].
make_alert([{_,_}|_] = AlertPL) ->
    Alert = sc_util:to_bin(sc_util:val(body, AlertPL)),
    ActionLocKey = sc_util:val('action-loc-key', AlertPL, null),
    LocKey = sc_util:to_bin(sc_util:val('loc-key', AlertPL, <<>>)),

    LocArgs = case sc_util:val('loc-args', AlertPL, []) of
        [] ->
            [];
        [_|_] = Args ->
            [sc_util:to_bin(Arg) || Arg <- Args]
    end,

    LaunchImage = sc_util:to_bin(sc_util:val('launch-image', AlertPL, <<>>)),

    Body = optional(<<"body">>, Alert) ++
           optional(<<"action-loc-key">>, ActionLocKey) ++
           optional(<<"loc-key">>, LocKey) ++
           optional(<<"loc-args">>, LocArgs) ++
           optional(<<"launch-image">>, LaunchImage),

    case Body of
        [] ->
            [];
        [_|_] ->
            [{<<"alert">>, Body}]
    end;

make_alert(<<>>) ->
    [];

make_alert(<<AlertText/binary>>) ->
    [{<<"alert">>, AlertText}];

make_alert(L) when is_list(L) ->
    make_alert(list_to_binary(L)).

-spec optional(K, V) -> Result when
      K :: binary(), V :: term(),
      Result :: [{K, V}].
optional(_K, V) when V =:= undefined orelse V =:= <<>> ->
    [];
optional(K, V) ->
    [{K, V}].

