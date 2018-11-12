# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- JSON API: `getinfo` now returns `num_peers` `num_pending_channels`,
  `num_active_channels` and `num_inactive_channels` fields.
- JSON API: use `\n\n` to terminate responses, for simplified parsing (pylightning now relies on this)
- Plugins: Added plugins to `lightningd` and implemented the option passthrough.

### Changed

- JSON API: `pay` and `decodepay` accept and ignore `lightning:` prefixes.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for
changes.

### Removed

### Fixed

- JSON API: uppercase invoices now parsed correctly (broken in 0.6.2).
- JSON API: commands are once again read even if one hasn't responded yet (broken in 0.6.2).
- Protocol: allow lnd to send `update_fee` before `funding_locked`.
- pylightning: handle multiple simultanous RPC replies reliably.

### Security


## [0.6.2] - 2018-10-20: "The Consensus Loving Nasal Daemon"

This release named by practicalswift.

### Added

- JSON API: `listpeers` has new field `scratch_txid`: the latest tx in channel.
- JSON API: `listpeers` has new array `htlcs`: the current live payments.
- JSON API: `listchannels` has two new fields: `message_flags` and `channel_flags`. This replaces `flags`.
- JSON API: `invoice` now adds route hint to invoices for incoming capacity (RouteBoost), and warns if insufficient capacity.
- JSON API: `listforwards` lists all forwarded payments, their associated channels, and fees.
- JSON API: `getinfo` shows forwarding fees earnt as `msatoshi_fees_collected`.
- Bitcoind: more parallelism in requests, for very slow nodes.
- Testing: fixed logging, cleaner interception of bitcoind, minor fixes.
- Protocol: we set and handle the new `htlc_maximum_msat` channel_update field.

### Changed

- Protocol: `channel_update` sent to disable channel only if we reject an HTLC.
- Protocol: we don't send redundant `node_announcement` on every new channel.
- Config: config file can override `lightning-dir` (makes sense with `--conf`).
- Config: `--conf` option is now relative to current directory, not `lightning-dir`.
- lightning-cli: `help <cmd>` prints basic information even if no man page found.
- JSON API: `getinfo` now reports global statistics about forwarded payments, including total fees earned and amounts routed.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for
changes.

- JSON RPC: `listchannels`' `flags` field. This has been split into two fields, see Added.
- JSON RPC: `global_features` and `local_features` fields: use `globalfeatures` and `localfeatures` as per BOLT #1.

### Removed

### Fixed

- Startup: more coherent complaint if daemon already running.
- Lightningd: correctly save full HTLCs across restarts; fixup old databases.
- JSON RPC: `getinfo` now shows correct Tor port.
- JSON RPC: `ping` now works even after one peer fails to respond.
- JSON RPC: `getroute` `fuzzpercent` and `pay` `maxfeepercent` can now be > 100.
- JSON RPC: `riskfactor` in `pay` and `getroute` no longer always treated as 1.
- JSON-RPC: `listpeers` was always reporting 0 for all stats.
- JSON RPC: `withdraw all` says `Cannot afford transaction` if you have
             absolutely no funds, rather than `Output 0 satoshis would be dust`.
- Protocol: don't send gossip about closed channels.
- Protocol: fix occasional deadlock when both peers flood with gossip.
- Protocol: fix occasional long delay on sending `reply_short_channel_ids_end`.
- Protocol: re-send `node_announcement` when address/alias/color etc change.
- Protocol: multiple HTLCs with the same payment_hash are handled correctly.
- Options: 'autotor' defaults to port 9051 if not specified.

### Security

## [0.6.1] - 2018-09-11: "Principled Opposition To Segwit"

This release named by ZmnSCPxj.

### Added

- Protocol: gossipd now deliberately delays spamming with `channel_update`.
- Protocol: liveness ping when we commit changes but peer is idle: speeds up
  failures and reduces forced closures.
- Protocol: `option_data_loss_protect` now supported to protect peers
  against being out-of-date.
- JSON API: Added description to invoices and payments (#1740).
- JSON API: `getinfo` has new fields `alias` and `color`.
- JSON API: `listpeers` has new fields `global_features` and `local_features`.
- JSON API: `listnodes` has new field `global_features`.
- JSON API: `ping` command to send a ping to a connected peer.
- JSON API: `feerates` command to retrieve current fee estimates.
- JSON API: `withdraw` and `fundchannel` can be given manual feerate.
- Config: `--conf` option to set config file.
- Documentation: Added CHANGELOG.md
- pylightning: RpcError now has `method` and `payload` fields.
- Sending lightningd a SIGHUP will make it reopen its `log-file`, if any.

### Changed

- Protocol: Fee estimates are now smoothed over time, to avoid sudden jumps.
- Config: You can only announce one address if each type (IPv4, IPv6,
  TORv2, TORv3).
- lightning-cli: the help command for a specific command now runs the
  `man` command.
- HSM: The HSM daemon now maintains the per-peer secrets, rather than
  handing them out.  It's still lax in what it signs though.
- connectd: A new daemon `lightning_connectd` handles connecting
  to/from peers, instead of `gossipd` doing that itself. `lightning_openingd` now
  handles peers immediately, even if they never actually open a channel.
- Test: `python-xdist` is now a dependency for tests.
- Logging: JSON connections no longer spam debug logs.
- Routing: We no longer consider channels that are not usable either because of
  their capacity or their `htlc_minimum_msat` parameter (#1777)
- We now try to connect to all known addresses for a peer, not just
  the one given or the first one announced.
- Crash logs are now placed one-per file like `crash.log.20180822233752`
- We will no longer allow withdrawing funds or funding channels if we
  do not have a fee estimate (eg. bitcoind not synced); use new `feerate` arg.

### Deprecated

### Removed

- JSON API: `listpeers` results no long have `alias` and `color` fields;
  they're in `listnodes` (we used to internally merge the information).
- JSON API: `listpeers` will never have `state` field (it accidentally
  used to exist and set to `GOSSIPING` before we opened a channel).
  `connected` will indicate if we're connected, and the `channels`
  array indicates individual channel states (if any).
- Config: `default-fee-rate` is no longer available; use explicit `feerate`
  option if necessary.
- Removed all Deprecated options from 0.6.

### Fixed

- Protocol: `node_announcement` multiple addresses are correctly ordered and uniquified.
- Protocol: if we can't estimate feerate, be almost infinitely
  tolerant of other side setting fees to avoid unilateral close.
- JSON API: `listnodes`: now displays node aliases and colors even if they
  don't advertise a network address
- JSON API: `fundchannel all`: now restricts to 2^24-1 satoshis rather than failing.
- JSON API: `listnodes`: now correctly prints `addresses` if more than
  one is advertised.
- Config: `bind-addr` of a publicly accessible network address was announced.
- When we reconnect and have to retransmit failing HTLCs, the errors weren't
  encrypted by us.
- `lightningd_config` man page is now installed by `make install`.
- Fixed crash when shutting down during opening a channel (#1737)
- Don't lose track of our own output when applying penalty transaction (#1738)
- Protocol: `channel_update` inside error messages now refers to correct channel.
- Stripping type prefix from `channel_update`s that are nested in an onion reply
  to be compatible with eclair and lnd (#1730).
- Failing tests no longer delete the test directory, to allow easier debugging
  (Issue: #1599)

### Security

## [0.6] - 2018-06-22: "I Accidentally The Smart Contract"

In the prehistory of c-lightning, no changelog was kept.  But major
JSON API changes are tracked.

This release named by Fabrice Drouin.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for
changes.

- Config: `port`.  Use `addr=:<portnum>`.
- Config: `ipaddr`.  Use `addr`.
- Config: `anchor-confirms`.  Use `funding-confirms`.
- Config: `locktime-blocks`.  Use `watchtime-blocks`.
- Protocol: on closing we allow out-of-range offers, prior to spec fix
  2018-01-30 ("BOLT 2: order closing-signed negotiation by making
  funder send first." `90241d9cf60a598eac8fd839ac81e4093a161272`)
- JSON API: `listinvoice` command.  Use `listinvoices`.
- JSON API: invoice result fields `paid_timestamp` and `expiry_time`.  Use
  `paid_at` and `expires_at`.
- JSON API: `invoice` command field `fallback`.  Use `fallbacks`.
- JSON API: `decodepay` result fields `timestamp` and `fallback`.  Use
  `created_at` and `fallbacks`.
- JSON API: payment result fields `timestamp`.  Use `created_at`.
- JSON API: `getinfo` result field `port`.  Use `binding` and `address` arrays.
- JSON API: `getlog` result field `creation_time`.  Use `created_at`.
- JSON API: `getpeers` result field `channel_reserve_satoshis`.  Use `their_channel_reserve_satoshis`.
- JSON API: `getpeers` result field `to_self_delay`.  Use `their_to_self_delay`.

## Older versions

There predate the BOLT specifications, and are only of vague historic interest:

1. [0.1] - 2015-08-08: "MtGox's Cold Wallet" (named by Rusty Russell)
2. [0.2] - 2016-01-22: "Butterfly Labs' Timely Delivery" (named by Anthony Towns)
3. [0.3] - 2016-05-25: "Nakamoto's Genesis Coins" (named by Braydon Fuller)
4. [0.4] - 2016-08-19: "Wright's Cryptographic Proof" (named by Chrstian Decker)
5. [0.5] - 2016-10-19: "Bitcoin Savings & Trust Daily Interest" (named by Glenn Willen)
6. [0.5.1] - 2016-10-21
7. [0.5.2] - 2016-11-21: "Bitcoin Savings & Trust Daily Interest II"

[Unreleased]: https://github.com/ElementsProject/lightning/compare/v0.6.2...HEAD
[0.6.2]: https://github.com/ElementsProject/lightning/releases/tag/v0.6.2
[0.6.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.6.1
[0.6]: https://github.com/ElementsProject/lightning/releases/tag/v0.6
[0.5.2]: https://github.com/ElementsProject/lightning/releases/tag/v0.5.2-2016-11-21
[0.5.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.5.1-2016-10-21
[0.5]: https://github.com/ElementsProject/lightning/releases/tag/v0.5-2016-10-19
[0.4]: https://github.com/ElementsProject/lightning/releases/tag/v0.4-2016-08-19
[0.3]: https://github.com/ElementsProject/lightning/releases/tag/v0.3-2016-05-26
[0.2]: https://github.com/ElementsProject/lightning/releases/tag/v0.2-2016-01-22
[0.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.1-2015-08-08
