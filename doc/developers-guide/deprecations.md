---
title: "Deprecated Feature"
slug: "deprecations"
excerpt: "Deprecated features and timeline for old feature removals."
hidden: false
---

| Name                                 | Type               | First Deprecated | Last Supported | Description                                                                                                                                                                     |
|--------------------------------------|--------------------|------------------|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| listconfigs.configlist               | Fields             | v23.08           | v24.08         | Instead of direct members with names equal the config variable, there's now a `configs` sub-object containing a member with details of each config setting                      |
| connection_notification.rawfields    | Notification Field | v23.08           | v24.08         | All notifications now wrap members in an object of the same name                                                                                                                |
| disconnection_notification.rawfields | Notification Field | v23.08           | v24.08         | All notifications now wrap members in an object of the same name                                                                                                                |
| block_added_notification.block       | Notification Field | v23.08           | v24.08         | All notifications now wrap members in an object of the same name                                                                                                                |
| accept-htlc-tlv-types                | Config             | v23.08           | v24.08         | New `accept-htlc-tlv-type` can be specified multiple times, which is cleaner                                                                                                    |
| bind-addr.torv3                      | Config             | v23.08           | v24.08         | `announce-addr` makes more sense for Tor addresses                                                                                                                              |
| addr.torv3                           | Config             | v23.08           | v24.08         | `announce-addr` makes more sense for Tor addresses                                                                                                                              |
| addr.socket                          | Config             | v23.08           | v24.08         | `bind-addr` makes more sense for local sockets since we cannot announce them                                                                                                    |
| announce-addr-dns                    | Config             | v23.08           | v24.08         | Use `bind-addr=dns:` to specify DNS announcements on a per-address basis                                                                                                        |
| rest-port.clnrest-prefix             | Config             | v23.11           | v24.11         | Autodetect where we need to rename `rest-port` to `clnrest-port` (added in v23.11)                                                                                              |
| rest-protocol.clnrest-prefix         | Config             | v23.11           | v24.11         | Autodetect where we need to rename `rest-protocol` to `clnrest-protocol` (added in v23.11)                                                                                      |
| rest-host.clnrest-prefix             | Config             | v23.11           | v24.11         | Autodetect where we need to rename `rest-host` to `clnrest-host` (added in v23.11)                                                                                              |
| rest-certs.clnrest-prefix            | Config             | v23.11           | v24.11         | Autodetect where we need to rename `rest-certs` to `clnrest-certs` (added in v23.11)                                                                                            |
| ....0-or-1                           | Config             | v23.08           | v24.08         | Boolean options (in plugins only) used to accept `0` or `1` in place of `true` or `false`                                                                                       |
| options.flag.default-not-false       | Getmanifest Reply  | v23.08           | v24.08         | `flag` options with a default which is not `false` (would be meaningless, since user can only set it to `true`                                                                  |
| plugin.nonumericids                  | Getmanifest Reply  | v23.08           | v24.08         | Plugins must specify that they can accept non-numeric command ids (numeric ids are deprecated)                                                                                  |
| listchannels.include_private         | Field(s)           | v24.02           | v24.08         | `listchannels` including private channels (now use listpeerchannels which gives far more detail)                                                                                |
| max-locktime-blocks                  | Config             | v24.05           | v24.11         | --max-locktime-blocks is now set to 2016 in the BOLT 4 spec                                                                                                                     |
| commando-rune                        | Command            | v23.08           | v25.02         | replaced with `lightning-createrune`                                                                                                   |
| commando-listrunes                   | Command            | v23.08           | v25.02         | replaced with `lightning-showrunes`                                                                                                    |
| commando-blacklist                   | Command            | v23.08           | v25.02         | replaced with `lightning-blacklistrune`                                                                                                |
| listpeers.features.option_anchors_zero_fee_htlc_tx | Field | v24.08          | v25.08         | Renamed to `option_anchors` in the spec: check for that in `features` instead                                                          |
| experimental-anchors                 | Config             | v24.02           | v25.02         | Now the default                                                                                                                        |
| experimental-onion-messages          | Config             | v24.08           | v25.02         | Now the default                                                                                                                        |
| decode.blinding                      | Field              | v24.11           | v25.05         | Renamed to `first_path_key` in BOLT 4 (available in `decode` from v24.11)                                                              |
| onion_message_recv.blinding          | Hook Field         | v24.11           | v25.05         | Renamed to `first_path_key` in BOLT 4 (available in hook from v24.11)                                                                  |
| decodepay                            | Command            | v24.11           | v25.11         | Use `decode` which is more powerful (since v23.05)                                                                                     |
| close.tx                             | Field              | v24.11           | v25.11         | Use txs array instead                                                                                                                  |
| close.txid                           | Field              | v24.11           | v25.11         | Use txids array instead                                                                                                                |
| experimental-offers                  | Config             | v24.11           | v25.05         | Now the default                                                                                                                        |

Inevitably there are features which need to change: either to be generalized, or removed when they can no longer be supported.

Types of deprecation:
* Command: an entire command is removed.  Usually replaced by a more generic or better-named one.
* Config: a commandline/configuration option is removed.  Usually made the default, or replaced by generalized or better-named.
* Field(s): a JSON field output.  We cannot detect if you are using these, of course.
* Parameter(s): a JSON RPC input.
* Getmanifest Reply: a field in the JSON reply which plugins give to `getmanifest`.
* Hook Return: a field/value in the JSON reply which plugins give to a plugin hook.
* Notification/Hook Field: a field in the JSON notification/hook to a plugin.

For each deprecation:
1. The deprecation is listed here, and in the CHANGELOG.md file.
2. We try to give at least 2 versions before removal.
3. Then one version where we issue a warning message if we detect a deprecated feature being used (not possible for deprecatred `Field` types).
4. At least one version where the deprecated feature can be explicit re-enabled using `i-promise-to-fix-broken-api-user=FEATURENAME`.


This is designed to minimize the chance that anyone will be surprised by a change!

You can also test earlier.  Deprecated features can be disabled in three ways:
1. `developer` mode changes the default deprecations to disabled globally.
2. `allow-deprecated-apis=` lets you disable (`false`) or re-enable (`true`) globally.
3. The `deprecations` JSON API can disable/re-enable deprecations for a specific client (added in *v24.02*).
