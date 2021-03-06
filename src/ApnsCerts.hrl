%% Generated by the Erlang ASN.1 compiler version:4.0.2
%% Purpose: Erlang record definitions for each named and unnamed
%% SEQUENCE and SET, and macro definitions for each value
%% definition,in module ApnsCerts



-ifndef(_APNSCERTS_HRL_).
-define(_APNSCERTS_HRL_, true).

-record('ApplePushExtension',{
extnID, critical = asn1_DEFAULT, extnValue}).

-record('ApnsTopicType',{
name}).

-define('push-certs', {1,2,840,113635,100,6,3}).
-define('id-apns-development', {1,2,840,113635,100,6,3,1}).
-define('id-apns-production', {1,2,840,113635,100,6,3,2}).
-define('id-apns-app-id-suffix', {1,2,840,113635,100,6,3,3}).
-define('id-apns-bundle-info', {1,2,840,113635,100,6,3,4}).
-define('id-apns-topics', {1,2,840,113635,100,6,3,6}).
-endif. %% _APNSCERTS_HRL_
