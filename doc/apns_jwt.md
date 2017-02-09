

# Module apns_jwt #
* [Description](#description)
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

This module creates a JWT suitable for use with APNS.

Copyright (c) 2016 Silent Circle

__Authors:__ Edwin Fine ([`efine@silentcircle.com`](mailto:efine@silentcircle.com)).

<a name="types"></a>

## Data Types ##




### <a name="type-alg">alg()</a> ###


<pre><code>
alg() = <a href="#type-bstring">bstring()</a>
</code></pre>




### <a name="type-apns_jwt_ctx">apns_jwt_ctx()</a> ###


<pre><code>
apns_jwt_ctx() = #apns_jwt_ctx{}
</code></pre>




### <a name="type-base64_urlencoded">base64_urlencoded()</a> ###


<pre><code>
base64_urlencoded() = <a href="#type-bstring">bstring()</a>
</code></pre>




### <a name="type-bstring">bstring()</a> ###


<pre><code>
bstring() = binary()
</code></pre>




### <a name="type-context">context()</a> ###


__abstract datatype__: `context()`




### <a name="type-ec_private_key">ec_private_key()</a> ###


<pre><code>
ec_private_key() = #'ECPrivateKey'{}
</code></pre>




### <a name="type-iat">iat()</a> ###


<pre><code>
iat() = <a href="#type-posix_time">posix_time()</a>
</code></pre>




### <a name="type-input_context">input_context()</a> ###


<pre><code>
input_context() = <a href="#type-output_context">output_context()</a> | <a href="#type-apns_jwt_ctx">apns_jwt_ctx()</a>
</code></pre>




### <a name="type-iss">iss()</a> ###


<pre><code>
iss() = <a href="#type-bstring">bstring()</a>
</code></pre>




### <a name="type-jose_header">jose_header()</a> ###


<pre><code>
jose_header() = <a href="#type-json">json()</a>
</code></pre>




### <a name="type-json">json()</a> ###


<pre><code>
json() = <a href="#type-bstring">bstring()</a>
</code></pre>




### <a name="type-jws_payload">jws_payload()</a> ###


<pre><code>
jws_payload() = <a href="#type-json">json()</a>
</code></pre>




### <a name="type-jws_signature">jws_signature()</a> ###


<pre><code>
jws_signature() = <a href="#type-base64_urlencoded">base64_urlencoded()</a>
</code></pre>




### <a name="type-jws_signing_input">jws_signing_input()</a> ###


<pre><code>
jws_signing_input() = <a href="#type-bstring">bstring()</a>
</code></pre>




### <a name="type-jwt">jwt()</a> ###


<pre><code>
jwt() = <a href="#type-bstring">bstring()</a>
</code></pre>




### <a name="type-key">key()</a> ###


<pre><code>
key() = term()
</code></pre>




### <a name="type-kid">kid()</a> ###


<pre><code>
kid() = <a href="#type-bstring">bstring()</a>
</code></pre>




### <a name="type-output_context">output_context()</a> ###


<pre><code>
output_context() = binary()
</code></pre>




### <a name="type-pem_encoded_key">pem_encoded_key()</a> ###


<pre><code>
pem_encoded_key() = <a href="#type-bstring">bstring()</a>
</code></pre>




### <a name="type-posix_time">posix_time()</a> ###


<pre><code>
posix_time() = pos_integer()
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#base64urldecode-1">base64urldecode/1</a></td><td></td></tr><tr><td valign="top"><a href="#base64urlencode-1">base64urlencode/1</a></td><td></td></tr><tr><td valign="top"><a href="#generate_private_key-0">generate_private_key/0</a></td><td>Generate a private key.</td></tr><tr><td valign="top"><a href="#iss-1">iss/1</a></td><td>Accessor for iss.</td></tr><tr><td valign="top"><a href="#jwt-1">jwt/1</a></td><td>Equivalent to <tt>jwt</tt>.</td></tr><tr><td valign="top"><a href="#jwt-3">jwt/3</a></td><td>Create a JWT for APNS usage, using the current erlang system time.</td></tr><tr><td valign="top"><a href="#key-1">key/1</a></td><td>Accessor for key.</td></tr><tr><td valign="top"><a href="#kid-1">kid/1</a></td><td>Accessor for kid.</td></tr><tr><td valign="top"><a href="#named_curve-0">named_curve/0</a></td><td></td></tr><tr><td valign="top"><a href="#new-3">new/3</a></td><td>Create a signing context from the parameters passed.</td></tr><tr><td valign="top"><a href="#public_key-1">public_key/1</a></td><td>Extract an EC public key from context or private key.</td></tr><tr><td valign="top"><a href="#verify-2">verify/2</a></td><td>Verify a JWT using a context.</td></tr><tr><td valign="top"><a href="#verify-4">verify/4</a></td><td>Verify a JWT using the kid, iss, and signing key.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="base64urldecode-1"></a>

### base64urldecode/1 ###

<pre><code>
base64urldecode(B64Urlencoded) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>B64Urlencoded = <a href="#type-base64_urlencoded">base64_urlencoded()</a></code></li><li><code>Result = binary()</code></li></ul>

<a name="base64urlencode-1"></a>

### base64urlencode/1 ###

<pre><code>
base64urlencode(Bin) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>Bin = binary()</code></li><li><code>Result = <a href="#type-base64_urlencoded">base64_urlencoded()</a></code></li></ul>

<a name="generate_private_key-0"></a>

### generate_private_key/0 ###

<pre><code>
generate_private_key() -&gt; <a href="#type-ec_private_key">ec_private_key()</a>
</code></pre>
<br />

Generate a private key. This is mostly useful for testing.

<a name="iss-1"></a>

### iss/1 ###

<pre><code>
iss(Context) -&gt; Iss
</code></pre>

<ul class="definitions"><li><code>Context = <a href="#type-input_context">input_context()</a> | <a href="#type-apns_jwt_ctx">apns_jwt_ctx()</a></code></li><li><code>Iss = <a href="#type-iss">iss()</a></code></li></ul>

Accessor for iss.

<a name="jwt-1"></a>

### jwt/1 ###

<pre><code>
jwt(Context) -&gt; JWT
</code></pre>

<ul class="definitions"><li><code>Context = <a href="#type-input_context">input_context()</a></code></li><li><code>JWT = <a href="#type-jwt">jwt()</a></code></li></ul>

Equivalent to `jwt`.

<a name="jwt-3"></a>

### jwt/3 ###

<pre><code>
jwt(KID, Issuer, SigningKey) -&gt; JWT
</code></pre>

<ul class="definitions"><li><code>KID = <a href="#type-kid">kid()</a></code></li><li><code>Issuer = <a href="#type-iss">iss()</a></code></li><li><code>SigningKey = <a href="#type-pem_encoded_key">pem_encoded_key()</a> | <a href="#type-ec_private_key">ec_private_key()</a></code></li><li><code>JWT = <a href="#type-jwt">jwt()</a></code></li></ul>

Create a JWT for APNS usage, using the current erlang system time.
This is signed with ECDSA using the P-256 curve and the ES256 algorithm.


#### <a name="Parameters">Parameters</a> ####



<dd><code>KID :: binary()</code></dd>




<dt>This is the key ID of the private APNS key downloaded from the Apple
developer portal.</dt>




<dd><code>Issuer :: binary()</code></dd>




<dt>This is the Apple Team ID from the Apple developer portal.</dt>




<dd><code>SigningKey:: pem_encoded_key() | ec_private_key()</code></dd>




<dt>This is the private key downloaded from the Apple
developer portal, either PEM-encoded as downloaded, or as
an #'ECPrivateKey{}' record.</dt>



<a name="key-1"></a>

### key/1 ###

<pre><code>
key(Context) -&gt; Key
</code></pre>

<ul class="definitions"><li><code>Context = <a href="#type-input_context">input_context()</a> | <a href="#type-apns_jwt_ctx">apns_jwt_ctx()</a></code></li><li><code>Key = <a href="#type-key">key()</a></code></li></ul>

Accessor for key.

<a name="kid-1"></a>

### kid/1 ###

<pre><code>
kid(Context) -&gt; KID
</code></pre>

<ul class="definitions"><li><code>Context = <a href="#type-input_context">input_context()</a> | <a href="#type-apns_jwt_ctx">apns_jwt_ctx()</a></code></li><li><code>KID = <a href="#type-kid">kid()</a></code></li></ul>

Accessor for kid.

<a name="named_curve-0"></a>

### named_curve/0 ###

<pre><code>
named_curve() -&gt; {namedCurve, OID::tuple()}
</code></pre>
<br />

<a name="new-3"></a>

### new/3 ###

<pre><code>
new(KID, Issuer, SigningKey) -&gt; Context
</code></pre>

<ul class="definitions"><li><code>KID = <a href="#type-kid">kid()</a></code></li><li><code>Issuer = <a href="#type-iss">iss()</a></code></li><li><code>SigningKey = <a href="#type-pem_encoded_key">pem_encoded_key()</a> | <a href="#type-ec_private_key">ec_private_key()</a></code></li><li><code>Context = <a href="#type-context">context()</a></code></li></ul>

Create a signing context from the parameters passed. This can
be used later to create a JWT.


#### <a name="Parameters">Parameters</a> ####



<dd><code>KID :: binary()</code></dd>




<dt>This is the key ID of the private APNS key downloaded from the Apple
developer portal.</dt>




<dd><code>Issuer :: binary()</code></dd>




<dt>This is the Apple Team ID from the Apple developer portal.</dt>




<dd><code>SigningKey :: pem_encoded_key()</code></dd>




<dt>This is the PEM-encoded private key downloaded from the Apple
developer portal.</dt>



<a name="public_key-1"></a>

### public_key/1 ###

<pre><code>
public_key(Opaque) -&gt; PublicKey
</code></pre>

<ul class="definitions"><li><code>Opaque = <a href="#type-ec_private_key">ec_private_key()</a> | <a href="#type-input_context">input_context()</a></code></li><li><code>PublicKey = {#'ECPoint'{}, {namedCurve, tuple()}}</code></li></ul>

Extract an EC public key from context or private key.

<a name="verify-2"></a>

### verify/2 ###

<pre><code>
verify(JWT, Context) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>JWT = <a href="#type-jwt">jwt()</a></code></li><li><code>Context = <a href="#type-input_context">input_context()</a> | <a href="#type-apns_jwt_ctx">apns_jwt_ctx()</a></code></li><li><code>Result = ok | {error, Reason}</code></li><li><code>Reason = term()</code></li></ul>

Verify a JWT using a context.
Return `ok` on success, `{error, {jwt_validation_failed, [binary()]}}`
if an error occurred. The list of binaries contains the failed keys of the
JWT.

<a name="verify-4"></a>

### verify/4 ###

<pre><code>
verify(JWT, KID, Iss, SigningKey) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>JWT = <a href="#type-jwt">jwt()</a></code></li><li><code>KID = <a href="#type-kid">kid()</a></code></li><li><code>Iss = <a href="#type-iss">iss()</a></code></li><li><code>SigningKey = <a href="#type-pem_encoded_key">pem_encoded_key()</a> | <a href="#type-ec_private_key">ec_private_key()</a></code></li><li><code>Result = ok | {error, Reason}</code></li><li><code>Reason = term()</code></li></ul>

Verify a JWT using the kid, iss, and signing key.

__See also:__ [verify/2](#verify-2).

