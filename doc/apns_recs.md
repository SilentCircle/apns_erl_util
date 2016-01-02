

# Module apns_recs #
* [Description](#description)

`apns_recs` provides exported records (exprecs) to avoid record
coupling by external users of these records.

Copyright (c) 2015 Silent Circle LLC

__Authors:__ Edwin Fine ([`efine@silentcircle.com`](mailto:efine@silentcircle.com)).

<a name="description"></a>

## Description ##

This exports the following
general functions:

```
  '#exported_records-'/0        '#is_record-'/2
  '#fromlist-'/2                '#new-'/1
  '#fromlist-apns_error'/1      '#new-apns_error'/0
  '#fromlist-apns_error'/2      '#new-apns_error'/1
  '#get-'/2                     '#pos-'/2
  '#get-apns_error'/2           '#pos-apns_error'/1
  '#info-'/1                    '#set-'/2
  '#info-'/2                    '#set-apns_error'/2
  '#info-apns_error'/1          module_info/0
  '#is_record-'/1               module_info/1
```

## apns_error record functions

```
  '#fromlist-apns_error'/1      '#new-apns_error'/0
  '#fromlist-apns_error'/2      '#new-apns_error'/1
  '#get-apns_error'/2           '#pos-apns_error'/1
  '#info-apns_error'/1'         '#set-apns_error'/2
```

Compiling this module requires the `exprecs` parse transform from
uwiger/parse_transform on github.