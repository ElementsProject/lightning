---
title: "Deprecated Features"
slug: "deprecated-features"
excerpt: "Deprecated features and timeline for old feature removals."
hidden: false
---

| Name                                 | Type               | First Deprecated | Last Supported | Description                                                                                                                                                                     |
|--------------------------------------|--------------------|------------------|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| listpeers.features.option_anchors_zero_fee_htlc_tx | Field | v24.08          | v25.09         | Renamed to `option_anchors` in the spec: check for that in `features` instead                                                          |
| decode.blinding                      | Field              | v24.11           | v25.05         | Renamed to `first_path_key` in BOLT 4 (available in `decode` from v24.11)                                                              |
| onion_message_recv.blinding          | Hook Field         | v24.11           | v25.05         | Renamed to `first_path_key` in BOLT 4 (available in hook from v24.11)                                                                  |
| decodepay                            | Command            | v24.11           | v25.12         | Use `decode` which is more powerful (since v23.05)                                                                                     |
| close.tx                             | Field              | v24.11           | v25.12         | Use txs array instead                                                                                                                  |
| close.txid                           | Field              | v24.11           | v25.12         | Use txids array instead                                                                                                                |
| experimental-offers                  | Config             | v24.11           | v25.05         | Now the default                                                                                                                        |
| xpay.ignore_bolt12_mpp               | Field              | v25.05           | v25.12         | Try MPP even if the BOLT12 invoice doesn't explicitly allow it (CLN didn't until 25.02)                                                |
| listpeerchannels.max_total_htlc_in_msat | Field           | v25.02           | v26.03         | Use our_max_total_htlc_out_msat                                                                                                              |
| wait.details                         | Field              | v25.05           | v26.06         | Use subsystem-specific object instead                                                                                                  |
| channel_state_changed.old_state.unknown | Notification Field | v25.05        | v26.03         | Value "unknown" is deprecated: field will be omitted instead                                                                           |
| coin_movement.tags                   | Notification Field | v25.09           | v26.09         | Use `primary_tag` (first tag) and `extra_tags` instead                                                                                 |
| coin_movement.utxo_txid              | Notification Field | v25.09           | v26.09         | Use `utxo` instead of `utxo_txid` & `vout`                                                                                             |
| coin_movement.txid                   | Notification Field | v25.09           | v26.09         | Use `spending_txid` instead                                                                                                            |
| channel_state_changed.null_scid         | Notification Field | v25.09        | v26.09         | In channel_state_changed notification, `short_channel_id` will be missing instead of `null`                                            |
| notification.payload                    | Notification Field | v25.09        | v26.09         | Notifications from plugins used to have fields in `payload` sub-object, now they are not (just like normal notifications)              |

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
