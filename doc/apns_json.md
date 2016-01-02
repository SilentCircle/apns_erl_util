

# Module apns_json #
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)

APNS JSON notification creation library.

Copyright (c) 2015 Silent Circle LLC

__Authors:__ Edwin Fine ([`efine@silentcircle.com`](mailto:efine@silentcircle.com)).

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#make_notification-1">make_notification/1</a></td><td>Create a notification consisting of a JSON binary suitable for
transmitting to the Apple Push Service.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="make_notification-1"></a>

### make_notification/1 ###

<pre><code>
make_notification(PL) -&gt; ApnsJsonNotification
</code></pre>

<ul class="definitions"><li><code>PL = [<a href="proplists.md#type-property">proplists:property()</a>]</code></li><li><code>ApnsJsonNotification = binary()</code></li></ul>

Create a notification consisting of a JSON binary suitable for
transmitting to the Apple Push Service.

Details on the notification proplist's properties follow.


#### <a name="Notification_Properties">Notification Properties</a> ####



<dt><code>alert</code></dt>




<dd>Binary or proplist. If a binary, it will be used
as the notification text. If a proplist, see below for
format of the proplist.</dd>




<dt><code>badge</code></dt>




<dd>Badge count (integer)</dd>




<dt><code>sound</code></dt>




<dd>Name of sound file in app bundle to play.</dd>




<dt><code>extra</code></dt>




<dd><p>Additional (optional) custom data, which must be an
object (Erlang proplist) as described in the table below.</p><p></p><table class="with-borders">
<tr>
<th><strong>json</strong></th><th><strong>erlang</strong></th>
</tr>
<tr>
<td> <code>number</code> </td>
<td> <code>integer()</code> and <code>float()</code></td>
</tr>
<tr>
<td> <code>string</code> </td>
<td> <code>binary()</code> </td>
</tr>
<tr>
<td> <code>true</code>, <code>false</code> and <code>null</code></td>
<td> <code>true</code>, <code>false</code> and <code>null</code></td>
</tr>
<tr>
<td> <code>array</code> </td>
<td> <code>[]</code> and <code>[JSON]</code></td>
</tr>
<tr>
<td> <code>object</code> </td>
<td> <code>[{}]</code> and <code>[{binary() OR atom(), JSON}]</code></td>
</tr>
</table>
</dd>




#### <a name="Alert_Properties">Alert Properties</a> ####
This describes the proplist that is expected if `'alert`' is not a
binary string (e.g. `<<"This is a message.">>`).



<dt><code>body</code></dt>



<dd>The alert text to be displayed (binary)</dd>




<dt><code>'action-loc-key</code>'</dt>




<dd>
If a string is specified, displays an alert with two buttons.
However, iOS uses the string as a key to get a localized string in the
current localization to use for the right button's title instead of
"View". If the value is <code>null</code>, the system displays an alert with a
single OK button that simply dismisses the alert when tapped. See
<a href="https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.md#//apple_ref/doc/uid/TP40008194-CH100-SW21">Localized Formatted Strings</a>
for more information.
</dd>




<dt><code>'loc-key</code>'</dt>




<dd>
A key to an alert-message string in a Localizable.strings file for
the current localization (which is set by the user's language
preference). The key string can be formatted with <code>%@</code> and <code>%n$@</code>
specifiers to take the variables specified in <code>'loc-args</code>'.
</dd>




<dt><code>'loc-args</code>'</dt>




<dd>
This array of binaries contains variable values to be substituted into
the format string defined in <code>'loc-key</code>'.
</dd>




<dt><code>'launch-image</code>'</dt>




<dd>
The filename of an image file in the application bundle; it may include
the extension or omit it. The image is used as the launch image when
users tap the action button or move the action slider. If this property
is not specified, the system either uses the previous snapshot, uses the
image identified by the <code>UILaunchImageFile</code> key in the application's
<code>Info.plist</code> file, or falls back to <code>Default.png</code>.
</dd>




### <a name="Examples_of_Notification_proplist">Examples of Notification proplist</a> ###


#### <a name="Simplest_Possible_Alert">Simplest Possible Alert</a> ####

```
  Notification = [
      {'alert', <<"Would you like to play a game?">>}
  ].
```


#### <a name="Alert_with_sound_and_badge">Alert with sound and badge</a> ####

```
  Notification = [
      {'alert', <<"Would you like to play a game?">>},
      {'badge', 1},
      {'sound', <<"wopr">>}
  ].
```


#### <a name="Alert_with_additional_custom_JSON_data">Alert with additional custom JSON data</a> ####

```
  Notification = [
      {'alert', <<"Would you like to play a game?">>},
      {'extra', [{<<"meta">>, [{<<"movie">>, <<"War Games">>}]]}
  ].
```


#### <a name="Localized_alert_using_'loc-key'_and_'loc-args'">Localized alert using 'loc-key' and 'loc-args'</a> ####

```
  Notification = [
      {'alert',
          [
              {'loc-key', <<"GAME_PLAY_REQUEST_FORMAT">>},
              {'loc-args', [<<"Jenna">>, <<"Frank">>]}
          ]
      },
      {'sound', <<"chime">>}
  ].
```


### <a name="More_Information">More Information</a> ###

For information on the keys in the proplist, see
[
Local and Push Notification Programming Guide
](https://developer.apple.com/library/ios/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/) (requires Apple Developer login).

