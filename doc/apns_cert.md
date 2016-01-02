

# Module apns_cert #
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)

APNS certificate utilities.

Copyright (c) 2015 Silent Circle LLC

__Authors:__ Edwin Fine ([`efine@silentcircle.com`](mailto:efine@silentcircle.com)).

<a name="description"></a>

## Description ##
This module provides functions to decode
and validate APNS PEM and DER format certificates, given a Bundle Seed ID
and the Bundle ID.  See
[`https://developer.apple.com/ios/manage/bundles/index.action`](https://developer.apple.com/ios/manage/bundles/index.action) (iOS
developer and iOS portal access required).<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#der_decode_cert-1">der_decode_cert/1</a></td><td>Decode DER binary into an #'OTPCertificate'{} record.</td></tr><tr><td valign="top"><a href="#get_cert_info-1">get_cert_info/1</a></td><td>Extract interesting APNS-related info from cert.</td></tr><tr><td valign="top"><a href="#pem_decode_certs-1">pem_decode_certs/1</a></td><td>Decode PEM binary into a list of #'OTPCertificate'{} records.</td></tr><tr><td valign="top"><a href="#validate-3">validate/3</a></td><td>Validate that the <code>BundleSeedID</code> and <code>BundleID</code> correspond to the
certificate data <code>CertData</code>.</td></tr></table>


<a name="functions"></a>

## Function Details ##

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
get_cert_info(OTPCert::#'OTPCertificate'{}) -&gt; #cert_info{}
</code></pre>
<br />

Extract interesting APNS-related info from cert.

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

