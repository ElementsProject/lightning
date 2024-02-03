---
title: "Deprecated Feature"
slug: "deprecations"
excerpt: "Deprecated features and timeline for old feature removals."
hidden: false
---

| Name                                 | Type               | First Deprecated | Last Supported | Description                                                                                                                                                                     |
|--------------------------------------|--------------------|------------------|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| delexpiredinvoice                    | Command            | v22.11           | v24.02         | `autoclean-once` is more powerful                                                                                                                                               |
| autocleaninvoice                     | Command            | v22.11           | v24.02         | `autoclean` is more general, does more than expired invoices                                                                                                                    |
| autocleaninvoice-cycle               | Config             | v22.11           | v24.02         | Now always once per hour: you can run `autoclean-once` regularly if you need.                                                                                                   |
| autocleaninvoice-expired-by          | Config             | v22.11           | v24.02         | `autoclean`'s `autoclean-expiredinvoices-age`                                                                                                                                   |
| feerates.delayed_to_us               | Field              | v23.05           | v24.02         | Not used with anchor outputs.                                                                                                                                                   |
| feerates.htlc_resolution             | Field              | v23.05           | v24.02         | Not used with anchor outputs.                                                                                                                                                   |
| listconfigs.configlist               | Fields             | v23.08           | v24.08         | Instead of direct members with names equal the config variable, there's now a `configs` sub-object containing a member with details of each config setting                      |
| feerate.NAME                         | Parameters         | v23.05           | v23.05         | Internal (unstable) parameters ("opening", "mutual_close", "delayed_to_us", "htlc_resolution", "penalty", "min_acceptable", "max_acceptable": use new-style names or `N`blocks. |
| invoice_payment_hook.failure_code    | Hook Return        | v22.08           | v23.02         | Plugins should generate a complete `failure_message` for better control                                                                                                         |
| htlc_Accepted_hook.failure_code      | Hook Return        | v0.8             | v23.02         | Plugins should generate a complete `failure_message` for better control                                                                                                         |
| connection_notification.rawfields    | Notification Field | v23.08           | v24.08         | All notifications now wrap members in an object of the same name                                                                                                                |
| disconnection_notification.rawfields | Notification Field | v23.08           | v24.08         | All notifications now wrap members in an object of the same name                                                                                                                |
| channel_opened.funding_locked        | Notification Field | v22.11           | v24.02         | Renamed to `channel_ready`, as per spec change (zero conf channels are ready before locked)                                                                                     |
| block_added_notification.block       | Notification Field | v23.08           | v24.08         | All notifications now wrap members in an object of the same name                                                                                                                |
| accept-htlc-tlv-types                | Config             | v23.08           | v24.08         | New `accept-htlc-tlv-type` can be specified multiple times, which is cleaner                                                                                                    |
| bind-addr.torv3                      | Config             | v23.08           | v24.08         | `announce-addr` makes more sense for Tor addresses                                                                                                                              |
| addr.torv3                           | Config             | v23.08           | v24.08         | `announce-addr` makes more sense for Tor addresses                                                                                                                              |
| addr.socket                          | Config             | v23.08           | v24.08         | `bind-addr` makes more sense for local sockets since we cannot announce them                                                                                                    |
| experimental-websocket-port          | Config             | v23.08           | v23.08         | Use `bind=ws:` to specify websocket ports on a per-port basis                                                                                                                   |
| announce-addr-dns                    | Config             | v23.08           | v24.08         | Use `bind-addr=dns:` to specify DNS announcements on a per-address basis                                                                                                        |
| rest-port.clnrest-prefix             | Config             | v23.11           | v24.11         | Autodetect where we need to rename `rest-port` to `clnrest-port` (added in v23.11)                                                                                              |
| rest-protocol.clnrest-prefix         | Config             | v23.11           | v24.11         | Autodetect where we need to rename `rest-protocol` to `clnrest-protocol` (added in v23.11)                                                                                      |
| rest-host.clnrest-prefix             | Config             | v23.11           | v24.11         | Autodetect where we need to rename `rest-host` to `clnrest-host` (added in v23.11)                                                                                              |
| rest-certs.clnrest-prefix            | Config             | v23.11           | v24.11         | Autodetect where we need to rename `rest-certs` to `clnrest-certs` (added in v23.11)                                                                                            |
| sendpay.channel.ignored              | Parameter          | v0.12            | v24.02         | Ignore channel specified in first hop and simply use peer id and select our own channel.                                                                                        |
| listpeers.channels                   | Field              | v23.02           | v24.02         | Channels are now in `listpeerchannels`                                                                                                                                          |
| ....0-or-1                           | Config             | v23.08           | v24.08         | Boolean options (in plugins only) used to accept `0` or `1` in place of `true` or `false`                                                                                       |
| options.flag.default-not-false       | Getmanifest Reply  | v23.08           | v24.08         | `flag` options with a default which is not `false` (would be meaningless, since user can only set it to `true`                                                                  |
| plugin.nonumericids                  | Getmanifest Reply  | v23.08           | v24.08         | Plugins must specify that they can accept non-numeric command ids (numeric ids are deprecated)                                                                                  |
| createrune.restrictions.string       | Parameter          | v23.05           | v24.02         | `restrictions` parameter must be an array of arrays, not an array of strings                                                                                                    |
| listchannels.include_private         | Field(s)           | v24.02           | v24.08         | `listchannels` including private channels (now use listpeerchannels which gives far more detail)                                                                                |
| estimatefees.dummy_null              | Field              | v23.05           | v24.05         | deprecated feerates are `null` (rather than missing) if fee estimate is not available                                                                                           |
| estimatefees.opening                 | Field              | v23.05           | v24.05         | `opening` feerate (implementation-specific, use modern feerates)                                                                                                                |
| estimatefees.mutual_close            | Field              | v23.05           | v24.05         | `mutual_close` feerate (implementation-specific, use modern feerates)                                                                                                           |
| estimatefees.unilateral_close        | Field              | v23.05           | v24.05         | `unilateral_close` feerate (implementation-specific, use modern feerates)                                                                                                       |
| estimatefees.delayed_to_us           | Field              | v23.05           | v24.05         | `delayed_to_us` feerate (implementation-specific, use modern feerates)                                                                                                          |
| estimatefees.htlc_resolution         | Field              | v23.05           | v24.05         | `htlc_resolution` feerate (implementation-specific, use modern feerates)                                                                                                        |
| estimatefees.penalty                 | Field              | v23.05           | v24.05         | `penalty` feerate (implementation-specific, use modern feerates)                                                                                                                |
| estimatefees.min_acceptable          | Field              | v23.05           | v24.05         | `min_acceptable` feerate (implementation-specific, use modern feerates)                                                                                                         |
| estimatefees.max_acceptable          | Field              | v23.05           | v24.05         | `max_acceptable` feerate (implementation-specific, use modern feerates)                                                                                                         |
| commando.missing_id                  | Parameter          | v23.02           | v24.02         | Incoming JSON commands without an `id` field                                                                                                                                    |
| offer.recurrence_base.at_prefix      | Parameter          | v24.02           | v24.05         | `recurrence_base` with `@` prefix (use `recurrence_start_any_period`)                                                                                                           |


Inevitably there are features which need to change: either to be generalized, or removed when they can no longer be supported.

Types of deprecation:
* Command: an entire command is removed.  Usually replaced by a more generic or better-named one.
* Config: a commandline/configuration option is removed.  Usually made the default, or replaced by generalized or better-named.
* Field(s): a JSON field output.  We cannot detect if you are using these, of course.
* Parameter(s): a JSON RPC input.
* Getmanifest Reply: a field in the JSON reply which plugins give to `getmanifest`.
* Hook Return: a field/value in the JSON reply which plugins give to a plugin hook.
* Notification Field: a field in the JSON notification to a plugin.

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
