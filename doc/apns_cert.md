

# Module apns_cert #
* [Description](#description)
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)

APNS certificate utilities.

Copyright (c) 2015-2016 Silent Circle

__Authors:__ Edwin Fine ([`efine@silentcircle.com`](mailto:efine@silentcircle.com)).

<a name="description"></a>

## Description ##
This module provides functions to decode and
validate APNS PEM and DER format certificates, given a Bundle Seed ID
and the Bundle ID.
See [`https://developer.apple.com`](https://developer.apple.com) for more information.
<a name="types"></a>

## Data Types ##




### <a name="type-asn1_tlv_rec">asn1_tlv_rec()</a> ###


<pre><code>
asn1_tlv_rec() = #asn1_tlv{}
</code></pre>




### <a name="type-cert_info">cert_info()</a> ###


<pre><code>
cert_info() = term()
</code></pre>

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#asn1_decode-1">asn1_decode/1</a></td><td></td></tr><tr><td valign="top"><a href="#asn1_decode_sequence-2">asn1_decode_sequence/2</a></td><td></td></tr><tr><td valign="top"><a href="#asn1_decode_tag-2">asn1_decode_tag/2</a></td><td></td></tr><tr><td valign="top"><a href="#asn1_tag_number-2">asn1_tag_number/2</a></td><td></td></tr><tr><td valign="top"><a href="#asn1_tag_octets-1">asn1_tag_octets/1</a></td><td></td></tr><tr><td valign="top"><a href="#decode_cert-1">decode_cert/1</a></td><td>Decode binary certificate data into an <code>#'OTPCertificate'{}</code>
record.</td></tr><tr><td valign="top"><a href="#der_decode_cert-1">der_decode_cert/1</a></td><td>Decode DER binary into an #'OTPCertificate'{} record.</td></tr><tr><td valign="top"><a href="#get_cert_info-1">get_cert_info/1</a></td><td>Extract interesting APNS-related info from cert.</td></tr><tr><td valign="top"><a href="#get_cert_info_map-1">get_cert_info_map/1</a></td><td>Extract more interesting APNS-related info from cert and
return in a map.</td></tr><tr><td valign="top"><a href="#pem_decode_certs-1">pem_decode_certs/1</a></td><td>Decode PEM binary into a list of #'OTPCertificate'{} records.</td></tr><tr><td valign="top"><a href="#validate-3">validate/3</a></td><td>Validate that the <code>BundleSeedID</code> and <code>BundleID</code> correspond to the
certificate data <code>CertData</code>.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="asn1_decode-1"></a>

### asn1_decode/1 ###

`asn1_decode(X1) -> any()`

<a name="asn1_decode_sequence-2"></a>

### asn1_decode_sequence/2 ###

<pre><code>
asn1_decode_sequence(Bytes, SeqLen) -&gt; {Seq, Rest}
</code></pre>

<ul class="definitions"><li><code>Bytes = binary()</code></li><li><code>SeqLen = integer()</code></li><li><code>Seq = [<a href="#type-asn1_tlv_rec">asn1_tlv_rec()</a>]</code></li><li><code>Rest = binary()</code></li></ul>

<a name="asn1_decode_tag-2"></a>

### asn1_decode_tag/2 ###

`asn1_decode_tag(T, X2) -> any()`

<a name="asn1_tag_number-2"></a>

### asn1_tag_number/2 ###

`asn1_tag_number(N, X2) -> any()`

<a name="asn1_tag_octets-1"></a>

### asn1_tag_octets/1 ###

`asn1_tag_octets(X1) -> any()`

<a name="decode_cert-1"></a>

### decode_cert/1 ###

<pre><code>
decode_cert(CertData) -&gt; Result
</code></pre>

<ul class="definitions"><li><code>CertData = binary()</code></li><li><code>Result = #'OTPCertificate'{} | {error, Reason::term()}</code></li></ul>

Decode binary certificate data into an `#'OTPCertificate'{}`
record.

<a name="der_decode_cert-1"></a>

### der_decode_cert/1 ###

<pre><code>
der_decode_cert(DerData::binary()) -&gt; #'OTPCertificate'{} | {error, Reason::term()}
</code></pre>
<br />

Decode DER binary into an #'OTPCertificate'{} record.

<a name="get_cert_info-1"></a>

### get_cert_info/1 ###

<pre><code>
get_cert_info(OTPCert) -&gt; CertInfo
</code></pre>

<ul class="definitions"><li><code>OTPCert = #'OTPCertificate'{}</code></li><li><code>CertInfo = <a href="#type-cert_info">cert_info()</a></code></li></ul>

Extract interesting APNS-related info from cert.

<a name="get_cert_info_map-1"></a>

### get_cert_info_map/1 ###

<pre><code>
get_cert_info_map(OTPCert) -&gt; CertInfo
</code></pre>

<ul class="definitions"><li><code>OTPCert = #'OTPCertificate'{}</code></li><li><code>CertInfo = #{}</code></li></ul>

Extract more interesting APNS-related info from cert and
return in a map.

<a name="pem_decode_certs-1"></a>

### pem_decode_certs/1 ###

<pre><code>
pem_decode_certs(PemData::binary()) -&gt; [#'OTPCertificate'{}] | {error, Reason::term()}
</code></pre>
<br />

Decode PEM binary into a list of #'OTPCertificate'{} records.

<a name="validate-3"></a>

### validate/3 ###

<pre><code>
validate(CertData::binary(), BundleSeedID::binary(), BundleID::binary()) -&gt; ok | {ErrorClass::atom(), Reason::term()}
</code></pre>
<br />

Validate that the `BundleSeedID` and `BundleID` correspond to the
certificate data `CertData`. `CertData` may be either PEM-encoded or
DER-encoded. If PEM-encoded, only one certificate is permitted in
the data.


#### <a name="Cert_Data">Cert Data</a> ####

Depending on whether or not the certificate is PEM or DER
encoded, you could load it as follows:

```
  {ok, PemData} = file:read_file("cert.pem").
  {ok, DerData} = file:read_file("aps_developer.cer").
```



#### <a name="Bundle_Seed_ID">Bundle Seed ID</a> ####

The bundle seed ID will be either in the form `^.{10}:.{10}$`,
such as `ABCDE12345:FGHIJ67890`, or
a bundle ID string such as `com.example.MyApp`. The caller is
expected to supply the right bundle seed ID format or the validation
will fail.

The Issuer CN is expected to be
`Apple Worldwide Developer Relations Certification Authority`
or the validation will fail.

