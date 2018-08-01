# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Documentation: Added CHANGELOG.md
- JSON API: `getinfo` has new fields `alias` and `color`.
- JSON API: `listpeers` has new fields `global_features` and `local_features`.
- JSON API:`listnodes` has new field `global_features`.
- Protocol: gossipd now deliberately delays spamming with `channel_update`.
- Config: `--conf` option to set config file.
- JSON API: Added description to invoices and payments (#1740).

### Changed

- Config: You can only announce one address if each type (IPv4, IPv6,
  TORv2, TORv3).
- Protocol: Fee estimates are now smoothed over time, to avoid sudden jumps.
- lightning-cli: the help command for a specific command now runs the
  `man` command.
- HSM: The HSM daemon now maintains the per-peer secrets, rather than
  handing them out.  It's still lax in what it signs though.
- connectd: A new daemon `lightningd_connectd` handles connecting
  to/from peers, instead of `gossipd` doing that itself.
- Test: `python-xdist` is now a dependency for tests.
- Logging: JSON connections no longer spam debug logs.
- Routing: We no longer consider channels that are not usable either because of
  their capacity or their `htlc_minimum_msat` parameter (#1777)
### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for
changes.

### Removed

- JSON API: `listpeers` results no long have `alias` and `color` fields;
  they're in `listnodes` (we used to internally merge the information).
- Removed all Deprecated options from 0.6.

### Fixed

- Options: `bind-addr` of a publicly accessible network address was announced.
- Protocol: `node_announcement` multiple addresses are correctly ordered and uniquified.
- JSON API: `listnodes`: now displays node aliases and colors even if they
  don't advertise a network address
- JSON API: `fundchannel all`: now restricts to 2^24-1 satoshis rather than failing.
- When we reconnect and have to retransmit failing HTLCs, the errors weren't
  encrypted by us.
- `lightningd_config` man page is now installed by `make install`.
- Fixed crash when shutting down during opening a channel (#1737)
- Don't lose track of our own output when applying penalty transaction (#1738)
- Protocol: `channel_update` inside error messages now refers to correct channel.
- Stripping type prefix from `channel_update`s that are nested in an onion reply
  to be compatible with eclair and lnd (#1730).
- JSON API: `listnodes`: now correctly prints `addresses` if more than
  one is advertised.
- Failing tests no longer delete the test directory, to allow easier debugging
  (Issue: #1599)

### Security

## [0.6] - 2018-06-22

In the prehistory of c-lightning, no changelog was kept.  But major
JSON API changes are tracked.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for
changes.

- Option: `port`.  Use `addr=:<portnum>`.
- Option: `ipaddr`.  Use `addr`.
- Option: `anchor-confirms`.  Use `funding-confirms`.
- Option: `locktime-blocks`.  Use `watchtime-blocks`.
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


[Unreleased]: https://github.com/ElementsProject/lightning/compare/v0.6...HEAD
[0.6]: https://github.com/ElementsProject/lightning/releases/tag/v0.6
