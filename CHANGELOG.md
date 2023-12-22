# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).


## [23.11.2] - 2023-12-22: "Bitcoin Orangepaper"

This is a hotfix release to address BOLT 11 invoice compatibility.

### Fixed

 - invoice: Force cltv field inclusion in BOLT 11 invoice, for old implementations still defaulting to 9 blocks ([#6957])

[#6957]: https://github.com/ElementsProject/lightning/pull/6957


## [23.11.1] - 2023-12-15: "Bitcoin Orangepaper"

This is a hotfix release to address a couple of issues in the release.

### Fixed

 - channeld: We could crash `closingd` by sending it a `channeld` message ([#6937])

[#6937]: https://github.com/ElementsProject/lightning/pull/6937

[v23.11.1]: https://github.com/ElementsProject/lightning/releases/tag/v23.11.1

## [23.11] - 2023-11-28: "Bitcoin Orangepaper"

This release named by Shahana Farooqui

### Added

 - JSON-RPC: `wait` now works for `forwards` infrastructure. ([#6753])
 - JSON-RPC: `wait` now works for `sendpays` infrastructure. ([#6753])
 - JSON-RPC: `check` now does much more checking on every command (not just basic parameter types). ([#6772])
 - `hsmtool`: new command `getemergencyrecover` to extract emergency.recover in bech32 format (clnemerge1...) ([#6773])
 - JSON-RPC: `datastoreusage`: returns the total bytes that are stored under a given key. ([#6442])
 - JSON-RPC: `decode` can now decode emergency.recover files (clnemerg1...) ([#6773])
 - Option: --commit-fee-offset to potentially reduce feerate update disagreements ([#6833])
 - Runes: `per=Nsec/min/hour/msec/usec/nsec` for general ratelimiting ([#6617])
 - JSON-RPC: `showrunes` new field `last_used` ([#6617])
 - JSON-RPC: `listforwards` new parameters `index`, `start` and `limit`. ([#6753])
 - JSON-RPC: `listforwards` fields `created_index` (old: `id`) and `updated_index`. ([#6753])
 - JSON-RPC: `listsendpays` new parameters `index`, `start` and `limit`. ([#6753])
 - JSON-RPC: `sendpay`, `listsendpays`, `delpay` new fields `created_index` (old: `id`) and `updated_index`. ([#6753])
 - JSON-RPC: `listinvoices` new field `paid_outpoint` if an invoice is paid onchain. ([#6421])
 - JSON-RPC: New `addpsbtoutput` command for creating a PSBT that can receive funds to the on-chain wallet. ([#6676])
 - Config: `invoices-onchain-fallback` to automatically add an onchain p2tr address to invoices, and allow that for payment. ([#6421])
 - JSON-RPC: `recover` command to force (unused) lightningd node to restart with `--recover` flag. ([#6772])
 - Config: `--recover` can take a 32-byte hex string, as well as codex32. ([#6772])
 - Config: `--developer` enables developer options and changes default to be "disable deprecated APIs". ([#6311])
 - Cln-RPC: Implement send_custom_notification to allow sending custom notifications to other plugins. ([#6135])
 - Cln-RPC: Add `wait` system to cln-rpc and cln-grpc. ([#6850])
 - Cln-RPC: Add `fetchinvoice` method to cln-rpc and cln-grpc. ([#6850])
 - Plugins: plugins can now specify (unknown) even messages we should accept from peers. ([#6689])
 - New configurable Content-Security-Policy (CSP) header for clnrest ([#6686])
 - New configurable Cross-Origin-Resource-Sharing(CSP) header for clnrest ([#6686])
 - hsmd protocol: Added hsmd_check_outpoint and hsmd_lock_outpoint ([#6760])


### Changed
 - JSON-RPC time fields now have full nanosecond precision (i.e. 9 decimals not 3): `listfowards` `received_time` `resolved_time` `listpays`/`listsendpays` `created_at`. ([#6617])
 - Config: `large-channels` is now the default, wumbology for all. ([#6783])
 - Plugins: `clnrest` config options `rest-certs`, `rest-protocol`, `rest-host`, `rest-port`, `rest-cors-origins`, `rest-csp` are all now prefixed with `cln` in order to avoid clashing with c-lightning-REST. (i.e., rest-port to clnrest-port) ([#6857])
 - JSON-RPC `listpeerchannels`.`inflights` may sometimes not include `scratch_txid` (mandatory -> optional) ([#6824])
 - JSON-RPC: `openchannel_update` will now echo back a result if there's a matching inflight record for this open. ([#6824])
 - JSON-RPC: `openchannel_signed` will now remember the details of a signed PSBT even if the peer is disconnected. ([#6824])
 - Plugins: `clnrest` can suppress the internal logging handler via `with_logging(false)` now ([#6797])
 - JSON-RPC: `checkrune` `rate` restriction is slightly stricter (exact division of time like `per`) ([#6710])
 - Protocol: use CPFP on peer's commitment tx if we can't broadcast our own. ([#6752])
 - Plugins: `clnrest` is upgraded to a poetry project. ([#6651])
 - Protocol: dual-funding now follows the next-funding-id rules. ([#6824])
 - Protocol: we no longer disconnect every time we receive a warning message. ([#6668])
 - Protocol: `invoice` no longer explicitly encodes `c` if it's the default (18) ([#6668])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

- Plugins: `clnrest` parameters `rest-port`, `rest-protocol`, `rest-host` and `rest-certs`: prefix `cln` to them ([#6876])


### Removed

 - Build: `--enable-developer` arg to configure (and DEVELOPER variables): use `./configure --enable-debugbuild` and `developer` setting at runtime. ([#6311])
 - JSON-RPC: `dev-sendcustommsg` (use `sendcustommsg`, which was added in v0.10.1) ([#6311])


### Fixed

 - Protocol: Some peer disconnects due to update_fee disagreements are avoided. ([#6833])
 - Plugins: `clnrest` websocket server notifications are available with restriction of `readonly` runes ([#6749])
 - Protocol: Issue splicing with pending / stuck HTLCs fixed. ([#6748])
 - Protocol: Implemented splicing restart logic for tx_signature and commitment_signed. Splice commitments are reworked in a manner incompatible with the last version. ([#6840])
 - Wallet: close change outputs show up immediately in `listfunds` so you can CPFP. ([#6734])
 - Restore any missing metadata that resource constrained signers stripped ([#6767])
 - JSON-RPC: Plugin notification `msat` fields in `invoice_payment` and `invoice_created` hooks now a number, not a string with "msat" suffix. ([#6884])
 - JSON-RPC: Plugin hook `payment` `msat` field is now a number, not a string with "msat" suffix. ([#6884])
 - JSON-RPC: fix `checkrune` when `method` parameter is the empty string. ([#6759])
 - JSON-RPC: `getroute` now documents that it ignores `fuzzpercent`. ([#6697])
 - Rune: use runes table `id` instead `runes_uniqueid` from `vars` because it returns incorrect unique id if rune/s migrated from datastore. ([#6715])
 - Added docs, testing, and some fixes related to splicing out, insufficent balance handling, and restarting during a splice. ([#6677])
 - The WIRE_HSMD_SIGN_SPLICE_TX HSM capability is now correctly checked. ([#6867])
 - Hsmtool: Fix segmentation fault when calling `getcodexsecret` without id. ([#6895])


### EXPERIMENTAL

 - Fixed anchor spending to be able to use more than one UTXO. ([#6780])
 - JSON-RPC: added new dual-funding state `DUALOPEND_OPEN_COMMITTED` ([#6628])


[#6752]: https://github.com/ElementsProject/lightning/pull/6752
[#6749]: https://github.com/ElementsProject/lightning/pull/6749
[#6753]: https://github.com/ElementsProject/lightning/pull/6753
[#6421]: https://github.com/ElementsProject/lightning/pull/6421
[#6689]: https://github.com/ElementsProject/lightning/pull/6689
[#6780]: https://github.com/ElementsProject/lightning/pull/6780
[#6651]: https://github.com/ElementsProject/lightning/pull/6651
[#6697]: https://github.com/ElementsProject/lightning/pull/6697
[#6617]: https://github.com/ElementsProject/lightning/pull/6617
[#6710]: https://github.com/ElementsProject/lightning/pull/6710
[#6767]: https://github.com/ElementsProject/lightning/pull/6767
[#6676]: https://github.com/ElementsProject/lightning/pull/6676
[#6686]: https://github.com/ElementsProject/lightning/pull/6686
[#6628]: https://github.com/ElementsProject/lightning/pull/6628
[#6797]: https://github.com/ElementsProject/lightning/pull/6797
[#6783]: https://github.com/ElementsProject/lightning/pull/6783
[#6772]: https://github.com/ElementsProject/lightning/pull/6772
[#6833]: https://github.com/ElementsProject/lightning/pull/6833
[#6677]: https://github.com/ElementsProject/lightning/pull/6677
[#6668]: https://github.com/ElementsProject/lightning/pull/6668
[#6748]: https://github.com/ElementsProject/lightning/pull/6748
[#6715]: https://github.com/ElementsProject/lightning/pull/6715
[#6824]: https://github.com/ElementsProject/lightning/pull/6824
[#6760]: https://github.com/ElementsProject/lightning/pull/6760
[#6442]: https://github.com/ElementsProject/lightning/pull/6442
[#6759]: https://github.com/ElementsProject/lightning/pull/6759
[#6773]: https://github.com/ElementsProject/lightning/pull/6773
[#6135]: https://github.com/ElementsProject/lightning/pull/6135
[#6311]: https://github.com/ElementsProject/lightning/pull/6311
[#6734]: https://github.com/ElementsProject/lightning/pull/6734
[#6850]: https://github.com/ElementsProject/lightning/pull/6850
[#6867]: https://github.com/ElementsProject/lightning/pull/6867
[#6857]: https://github.com/ElementsProject/lightning/pull/6857
[#6876]: https://github.com/ElementsProject/lightning/pull/6876
[#6840]: https://github.com/ElementsProject/lightning/pull/6840
[#6884]: https://github.com/ElementsProject/lightning/pull/6884
[#6895]: https://github.com/ElementsProject/lightning/pull/6895


## [23.08.1] - 2023-09-12: "Satoshi's Successor II"

Bugfix release for bad issues found since 23.08 which can't wait for 23.11, and some minor low-impact fixes (e.g. docker images, documentation, CI).


### Added

 - cln-rpc: `ShortChannelId` has Eq, PartialOrd, Ord and Hash traits ([#6662])
 - doc: documentation for REST interface (clnrest) ([#6631])


### Changed

 - JSON-RPC: `checkrune` `nodeid` parameter now optional ([#6622])


### Fixed

 - Protocol: Fixed a wrong number type being used in routes ([#6642])
 - JSON-RPC: `showrunes` on a specific rune would always say `stored`: false. ([#6640])
 - MacOS: `clnrest` now works ([#6605])
 - Build: test for `python3` or `python`, rather than assuming `python3` ([#6630])


### EXPERIMENTAL

  - Plugins: `renepay`: various minor fixes. ([#6632])


[#6605]: https://github.com/ElementsProject/lightning/pull/6605
[#6622]: https://github.com/ElementsProject/lightning/pull/6622
[#6630]: https://github.com/ElementsProject/lightning/pull/6630
[#6631]: https://github.com/ElementsProject/lightning/pull/6631
[#6632]: https://github.com/ElementsProject/lightning/pull/6632
[#6642]: https://github.com/ElementsProject/lightning/pull/6642
[#6640]: https://github.com/ElementsProject/lightning/pull/6640
[#6662]: https://github.com/ElementsProject/lightning/pull/6662
[v23.08.1]: https://github.com/ElementsProject/lightning/releases/tag/v23.08.1


## [v23.08] - 2023-08-23: "Satoshi's Successor"

This release named by Matt Morehouse.

### Added

 - Plugins: `renepay`: an experimental pay plugin implementing Pickhardt payments (`renepay` and `renepaystatus`). ([#6376])
 - Plugins: `clnrest`: a lightweight python rest API service. ([#6389])
 - JSON-RPC: `wait`: new generic command to wait for events. ([#6127])
 - JSON-RPC: `setchannel` adds a new `ignorefeelimits` parameter to allow peer to set arbitrary commitment transaction fees on a per-channel basis. ([#6398])
 - Config: A new opentracing system with minimal performance impact for performance tracing in productive systems: see doc/developers-guide/tracing-cln-performance.md ([#5492])
 - Plugins: `pay` will now pay your own invoices if you try. ([#6399])
 - JSON-RPC: `checkrune`: check rune validity for authorization; `createrune` to create/modify rune; `showrunes` to list existing runes; `blacklistrune` to revoke permission of rune ([#6403])
 - Protocol: When we send our own gossip when a peer connects, also send any incoming channel_updates. ([#6412])
 - Config: `log-level` can be specified on a per-logfile basis. ([#6406])
 - Config: `--recover` can restore a node from a codex32 secret ([#6302])
 - Tools: `hsmtool` `getcodexsecret` to extract node secret as codex32 secret ([#6466])
 - JSON-RPC: newaddr: p2tr option to create taproot addresses. ([#6035])
 - JSON-RPC: new command `setconfig` allows a limited number of configuration settings to be changed without restart. ([#6303])
 - JSON-RPC: `listconfigs` now has `configs` subobject with more information about each config option. ([#6243])
 - Config: `--regtest` option as alias for `--network=regtest` ([#6243])
 - Config: `accept-htlc-tlv-type` (replaces awkward-to-use `accept-htlc-tlv-types`) ([#6243])
 - Config: `bind=ws:...` to explicitly listen on a websocket. ([#6173])
 - Config: `bind` can now take `dns:` prefix to advertize DNS records. ([#6173])
 - Plugins: `sendpay` now allows self-payment of invoices, by specifying an empty route. ([#6399])
 - Plugins: plugins can subscribe to all notifications using "*". ([#6347])
 - Plugins: Pass the current known block height down to the getchaininfo call. ([#6181])
 - JSON-RPC: `listinvoices` has `limit` parameter for listing control. ([#6127])
 - JSON-RPC: `listinvoices` has `index` and `start` parameters for listing control. ([#6127])
 - JSON-RPC: `listpeerchannels` has a new field `ignore_fee_limits` ([#6398])
 - JSON-RPC: `shutdown` notification contains `shutdown` object (notification consistency) ([#6347])
 - JSON-RPC: `block_added` notification wraps fields in `block_added` object (notification consistency) ([#6388])
 - JSON-RPC: `connect` and `disconnect` notifications now wrap `id` field in a `connect`/`disconnect` object (consistency with other notifications) ([#6388])
 - JSON-RPC: `fundpsbt` and `utxopsbt` new parameter `opening_anchor_channel` so lightningd knowns it needs emergency reserve for anchors. ([#6334])
 - Config: `min-emergency-msat` setting for (currently experimental!) anchor channels, to keep funds in reserve for forced closes. ([#6334])
 - JSON-RPC: `feerates` has new fields `unilateral_anchor_close` to show the feerate used for anchor channels (currently experimental), and `unilateral_close_nonanchor_satoshis`. ([#6334])
 - cln-grpc: Added `staticbackup` support to cln-grpc ([#6507])


### Changed

 - Tools: Reckless can now install directly from local sources. ([#6393])
 - Protocol: We allow update_fail_malformed_htlc with invalid error codes (LND?) ([#6425])
 - Protocol: `invoice` will use channels for routehints even if peer says they're "disabled" (LND compat) ([#6556])
 - pyln-testing: The grpc dependencies are now optional. ([#6417])
 - Protocol: commando commands now allow a missing params field, instead of requiring an empty field. ([#6405])
 - Wallet: we now use taproot change addresses. ([#6035])
 - Plugins: `autoclean` configuration variables now settable with `setconfig`. ([#6303])
 - JSON-RPC: `fundchannel` and `multifundchannel` will refuse to spend funds below `min-emergency-msat` if we have any anchor channels (or are opening one). ([#6334])
 - JSON-RPC: `withdraw` will refuse to spend funds below `min-emergency-msat` if we have any anchor channels (and `all` will be reduced appropriately). ([#6334])
 - JSON-RPC: `fundpsbt` and `utxopsbt` will refuse to spend funds below `min-emergency-msat` if we have any anchor channels. ([#6334])
 - JSON-RPC: `feerates` `unilateral_close_satoshis` now assumes anchor channels if enabled (currently experimental). ([#6334])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON-RPC: `commando-rune`, `commando-listrunes` and `commando-blacklist` (use `createrune`, `showrunes` and `blacklistrune` ([#6403])
 - JSON-RPC: `connect`, `disconnect` and `block_added` notification fields outside the same-named object (use .connect/.disconnect/.block_added sub-objects) ([#6388])
 - `pay` has *undeprecated* paying a description-hash invoice without providing the description. ([#6337])
 - JSON-RPC: `listconfigs` direct fields, use `configs` sub-object and `set`, `value_bool`, `value_str`, `value_int`, or `value_msat` fields. ([#6243])
 - Config: boolean plugin options set to `1` or `0` (use `true` and `false` like non-plugin options). ([#6243])
 - Config: `accept-htlc-tlv-types` (use `accept-htlc-tlv-type` multiple times) ([#6243])
 - Config: `experimental-websocket-port`: use `--bind=ws::<portnum>`. ([#6173])
 - Config: bind-addr=xxx.onion and addr=xxx.onion, use announce-addr=xxx.onion (which was always equivalent). ([#6173])
 - Config: addr=/socketpath, use listen=/socketpath (which was always equivalent). ([#6173])
 - Config: `announce-addr-dns`; use `--bind-addr=dns:ADDR` for finer control. ([#6173])


### Removed

 - Plugins: `commando` no longer allows datastore ['commando', 'secret'] to override master secret (re-issue runes if you were using that!). ([#6431])
 - Plugins: pay: `pay` no longer splits based on common size, as it was causing issues in various scenarios. ([#6400])
 - Build: Support for python v<=3.7 & Ubuntu bionic ([#6414])


### Fixed

 - Protocol: Fix incompatibility with LND which prevented us opening private channels ([#6304])
 - Protocol: We no longer gossip about recently-closed channels (Eclair gets upset with this). ([#6413])
 - Protocol: We will close incoming HTLCs early if the outgoing HTLC is stuck onchain long enough, to avoid cascating failure. ([#6378])
 - JSON-RPC: `close` returns a `tx` field with witness data populated (i.e. signed). ([#6468])
 - Protocol: When we send our own gossip when a peer connects, send our node_announcement too (regression in v23.05) ([#6412])
 - Protocol: `dualopend`: Fix behavior for tx-aborts. No longer hangs, appropriately continues re-init of RBF requests without reconnection msg exchange. ([#6461])
 - Protocol: Node announcements are refreshed more reliably. ([#6454])
 - Build: Small fix for Mac OS building ([#6253])
 - msggen: `listpays` now includes the missing `amount_msat` and `amount_sent_msat` fields ([#6441])
 - Protocol: Adding a >0 version witness program to a fallback address now is *just* the witness program, as per bolt11 spec ([#6435])
 - JSON-RPC: `sendonion` and `sendpay` will now consider amounts involved when using picking one channel for a peer ([#6428])
 - Plugins: pay: We now track spendable amounts when routing on both the local alias as well as the short channel ID ([#6428])
 - Plugins: pay: will still use an invoice routehint if path to it doesn't take 1-msat payments. ([#6579])
 - Config: `log-level` filters now apply correctly to messages from `connectd`. ([#6406])
 - Lightnind: don't infinite loop on 32 bit platforms if only invoices are expiring after 2038. ([#6361])
 - JSON-RPC: `pay` and `decodepay` with description now correctly handle JSON escapes (e.g " inside description) ([#6337])
 - Plugins: `commando` runes can now compare integer parameters using '<' and '>' as expected. ([#6295])
 - Plugins: reloaded plugins get passed any vars from configuration files. ([#6243])
 - JSON-RPC: `listconfigs` `rpc-file-mode` no longer has gratuitous quotes (e.g. "0600" not "\"0600\""). ([#6243])
 - JSON-RPC: `listconfigs` `htlc-minimum-msat`, `htlc-maximum-msat` and `max-dust-htlc-exposure-msat` fields are now numbers, not strings. ([#6243])
 - Protocol: We may propose mutual close transaction which has a slightly higher fee than the final commitment tx (depending on the outputs, e.g. two taproot outputs). ([#6547])
 - Protocol: We now close connection with a peer if adding an HTLC times out (which may be a TCP connectivity issue). ([#6520])
 - Plugins: we clean up properly if a plugin fails to start, and we don't kill all processes if it's from `plugin startdir`. ([#6570])
 - lightning-cli: properly returns help without argument ([#6568])


### EXPERIMENTAL

 - Build: all experimental features are now runtime-enabled; no more `./configure --enable-experimental-features` ([#6209])
 - Protocol: `experimental-splicing` to enable splicing & resizing of active channels. ([#6253])
 - protocol: `experimental-anchors` to support zero-fee-htlc anchors (`option_anchors_zero_fee_htlc_tx`). ([#6334])
 - Protocol: Removed support for advertizing websocket addresses in gossip. ([#6173])
 - Crash: Fixed crash in dual-funding. ([#6273])
 - Config: `experimental-upgrade-protocol` enables simple channel upgrades. ([#6209])
 - Config: `experimental-quiesce` enables quiescence, for testing. ([#6209])


[#5492]: https://github.com/ElementsProject/lightning/pull/5492
[#6035]: https://github.com/ElementsProject/lightning/pull/6035
[#6127]: https://github.com/ElementsProject/lightning/pull/6127
[#6173]: https://github.com/ElementsProject/lightning/pull/6173
[#6181]: https://github.com/ElementsProject/lightning/pull/6181
[#6209]: https://github.com/ElementsProject/lightning/pull/6209
[#6243]: https://github.com/ElementsProject/lightning/pull/6243
[#6253]: https://github.com/ElementsProject/lightning/pull/6253
[#6273]: https://github.com/ElementsProject/lightning/pull/6273
[#6295]: https://github.com/ElementsProject/lightning/pull/6295
[#6302]: https://github.com/ElementsProject/lightning/pull/6302
[#6303]: https://github.com/ElementsProject/lightning/pull/6303
[#6304]: https://github.com/ElementsProject/lightning/pull/6304
[#6310]: https://github.com/ElementsProject/lightning/pull/6310
[#6334]: https://github.com/ElementsProject/lightning/pull/6334
[#6337]: https://github.com/ElementsProject/lightning/pull/6337
[#6347]: https://github.com/ElementsProject/lightning/pull/6347
[#6361]: https://github.com/ElementsProject/lightning/pull/6361
[#6376]: https://github.com/ElementsProject/lightning/pull/6376
[#6378]: https://github.com/ElementsProject/lightning/pull/6378
[#6388]: https://github.com/ElementsProject/lightning/pull/6388
[#6389]: https://github.com/ElementsProject/lightning/pull/6389
[#6393]: https://github.com/ElementsProject/lightning/pull/6393
[#6398]: https://github.com/ElementsProject/lightning/pull/6398
[#6399]: https://github.com/ElementsProject/lightning/pull/6399
[#6400]: https://github.com/ElementsProject/lightning/pull/6400
[#6403]: https://github.com/ElementsProject/lightning/pull/6403
[#6405]: https://github.com/ElementsProject/lightning/pull/6405
[#6406]: https://github.com/ElementsProject/lightning/pull/6406
[#6412]: https://github.com/ElementsProject/lightning/pull/6412
[#6413]: https://github.com/ElementsProject/lightning/pull/6413
[#6414]: https://github.com/ElementsProject/lightning/pull/6414
[#6417]: https://github.com/ElementsProject/lightning/pull/6417
[#6425]: https://github.com/ElementsProject/lightning/pull/6425
[#6428]: https://github.com/ElementsProject/lightning/pull/6428
[#6431]: https://github.com/ElementsProject/lightning/pull/6431
[#6435]: https://github.com/ElementsProject/lightning/pull/6435
[#6441]: https://github.com/ElementsProject/lightning/pull/6441
[#6454]: https://github.com/ElementsProject/lightning/pull/6454
[#6461]: https://github.com/ElementsProject/lightning/pull/6461
[#6466]: https://github.com/ElementsProject/lightning/pull/6466
[#6468]: https://github.com/ElementsProject/lightning/pull/6468
[#6507]: https://github.com/ElementsProject/lightning/pull/6507
[#6520]: https://github.com/ElementsProject/lightning/pull/6520
[#6547]: https://github.com/ElementsProject/lightning/pull/6547
[#6556]: https://github.com/ElementsProject/lightning/pull/6556
[#6579]: https://github.com/ElementsProject/lightning/pull/6579
[#6570]: https://github.com/ElementsProject/lightning/pull/6570
[#6568]: https://github.com/ElementsProject/lightning/pull/6568
[#6564]: https://github.com/ElementsProject/lightning/pull/6564
[v23.08]: https://github.com/ElementsProject/lightning/releases/tag/v23.08


## [23.05.2] - 2023-06-21: "Austin Texas Agreement(ATXA) III"

Bugfix release for bad issues found since 23.05.1 which can't wait for 23.08.

### Fixed

 - JSON-RPC: `pay` and `decodepay` with description now correctly handle JSON escapes (e.g " inside description)
 - JSON-RPC: `pay` has *undeprecated* paying a description-hash invoice without providing the description (since it didn't work reliably until now!)
 - GRPC: `listpeers` sometimes could fail on unknown HTLC states.

### EXPERIMENTAL
 -  Fixed compilation error when `--enable-experimental-features` configured.


## [23.05.1] - 2023-06-05: "Austin Texas Agreement(ATXA) II"

Bugfix release for bad issues found since 23.05 which can't wait for 23.08.

### Fixed

 - Fixed crash (memory corruption!) in `listtransactions` ([#6304])
 - Don't crash on gossip store deletion fail ([#6297])
 - Fix incompatibility with LND which prevented us opening private channels ([#6304])

### EXPERIMENTAL

 - Fixed crash in dual-funding. ([#6273])

[#6273]: https://github.com/ElementsProject/lightning/pull/6273
[#6304]: https://github.com/ElementsProject/lightning/pull/6304
[#6297]: https://github.com/ElementsProject/lightning/pull/6297
[#6304]: https://github.com/ElementsProject/lightning/pull/6304

## [23.05] - 2023-05-10: "Austin Texas Agreement(ATXA)"

This release named by @instagibbs

NOTE 1: This release contains breaking changes of the Great Msat migration started in v0.12.0, so "msat" fields are no longer strings with "msat" appended, but simply integers.

### Added

 - Protocol: blinded payments are now supported by default (not just with `--experimental-onion-messages`) ([#6138])
 - Protocol: we now always double-check bitcoin addresses are correct (no memory errors!) before issuing them. ([#5708])
 - JSON-RPC: PSBTv2 support for `fundchannel_complete`, `openchannel_update`, `reserveinputs`, `sendpsbt`, `signpsbt`, `withdraw` and `unreserveinputs` parameter `psbt`, `openchannel_init` and `openchannel_bump` parameter `initialpsbt`, `openchannel_signed` parameter `signed_psbt` and `utxopsbt` parameter `utxopsbt` ([#5898])
 - Plugins: `commando-blacklist` new command to disable select runes. ([#6124])
 - Plugins: `commando-listrunes` new command to show issued runes. ([#6124])
 - JSON-RPC: `listclosedchannels` new command to show old, dead channels we previously had with peers. ([#5967])
 - JSON-RPC: `close`, `fundchannel`, `fundpsbt`, `multifundchannel`, `multiwithdraw`, `txprepare`, `upgradewallet`, `withdraw` now allow "minimum" and NN"blocks" as `feerate` (`feerange` for `close`). ([#6120])
 - JSON-RPC: `feerates` added `floor` field for current minimum feerate bitcoind will accept ([#6120])
 - JSON-RPC: `feerates` `estimates` array shows fee estimates by blockcount from underlying plugin (usually *bcli*). ([#6120])
 - Plugins: `estimatefees` can return explicit `fee_floor` and `feerates` by block number. ([#6120])
 - JSON-RPC: `listfunds` now has a `channel_id` field. ([#6029])
 - JSON-RPC: `listpeerchannels` now has `channel_type` field. ([#5967])
 - JSON-RPC: `sql` now includes `listclosedchannels`. ([#5967])
 - `pyln-client`: Improvements on the gossmap implementation ([#6012])
 - `hsmtool`: `makerune` new command to make a master rune for a node. ([#6097])
 - JSON-RPC: `setpsbtversion`: new command to aid debugging and compatibility ([#5898])
 - `grpc`: Added mapping for `listpeerchannels`, `listclosedchannels`, `decode` and `decodepay` RPC methods ([#6229])


### Changed

 - `reckless`: Added support for node.js plugin installation ([#6158])
 - `reckless`: Added support for networks beyond bitcoin and regtest ([#6110])
 - JSON-RPC: elements network PSET now only supports PSETv2. ([#5898])
 - JSON-RPC: `close`, `fundchannel`, `fundpsbt`, `multifundchannel`, `multiwithdraw`, `txprepare`, `upgradewallet`, `withdraw` `feerate` (`feerange` for `close`) value *slow* is now 100 block-estimate, not half of 100-block estimate. ([#6120])
 - Protocol: spending unilateral close transactions now use dynamic fees based on deadlines (and RBF), instead of fixed fees. ([#6120])
 - Protocol: Allow slight overpaying, even with MPP, as spec now recommends. ([#6138])
 - `msggen`: The generated interfaces `cln-rpc` anc `cln-grpc` can now work with a range of versions rather than having to match the CLN version ([#6142])
 - `grpc`: The mTLS private keys are no longer group-readable ([#6075])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON-RPC: `close`, `fundchannel`, `fundpsbt`, `multifundchannel`, `multiwithdraw`, `txprepare`, `upgradewallet`, `withdraw` `feerate` (`feerange` for `close`) expressed as, "delayed_to_us", "htlc_resolution", "max_acceptable" or "min_acceptable".  Use explicit block counts or *slow*/*normal*/*urgent*/*minimum*. ([#6120])
 - Plugins: `estimatefees` returning feerates by name (e.g. "opening"); use `fee_floor` and `feerates`. ([#6120])
 - Protocol: Not setting `option_scid_alias` in `option_channel` `channel_type` for unannounced channels. ([#6136])


### Removed

 - JSON-RPC: the "msat" suffix on millisatoshi fields, as deprecated in v0.12.0. ([#5986], [#6245])
 - JSON-RPC: all the non-msat-named millisatoshi fields deprecated in v0.12.0. ([#5986])
 - JSON-RPC: `listpeers`.`local_msat` and `listpeers`.`remote_msat` (deprecated v0.12.0) ([#5986])
 - JSON-RPC: `checkmessage` now always returns an error when the pubkey is not specified and it is unknown in the network graph (deprecated v0.12.0) ([#5986])
 - JSON-RPC: require the `"jsonrpc": "2.0"` property (requests without this deprecated in v0.10.2). ([#5986])


### Fixed

 - Plugins: `bcli` now tells us the minimal possible feerate, such as with mempool congestion, rather than assuming 1 sat/vbyte. ([#6120])
 - `lightningd`: don't log gratuitous "Peer transient failure" message on first connection after restart. ([#6140])
 - `channeld`: no longer spin and spam logs when waiting for revoke_and_ack. ([#6107])
 - Plugin: `autoclean` now also cleans forwards with status `local_failed` ([#6109])
 - Protocol: we will upfront reject channel_open which asks for a zeroconf channel unless we are going to do a zerconf channel. ([#6136])
 - Protocol: We now correctly accept the `option_scid_alias` bit in `open_channel` `channel_type`. ([#6136])
 - JSON-RPC: `feerates` document correctly that urgent means 6 blocks (not 2), and give better feerate examples. ([#6170])
 - `wallet`: we no longer make txs below minrelaytxfee or mempoolminfee. ([#6073])
 - `delpay`: be more pedantic about delete logic by allowing delete payments by status directly on the database. ([#6115])
 - Plugins: `bookkeeper` onchain fees calculation was incorrect with PostgresQL. ([#6128])
 - `clnrs`: Fixed an issue converting routehints in keysend ([#6154])
 - Build: Compilation with upcoming gcc 13 ([#6184])


### EXPERIMENTAL

 - fetchinvoice: fix: do not ignore the `quantity` field ([#6090])


[#6120]: https://github.com/ElementsProject/lightning/pull/6120
[#6138]: https://github.com/ElementsProject/lightning/pull/6138
[#5967]: https://github.com/ElementsProject/lightning/pull/5967
[#5898]: https://github.com/ElementsProject/lightning/pull/5898
[#5986]: https://github.com/ElementsProject/lightning/pull/5986
[#6245]: https://github.com/ElementsProject/lightning/pull/6245
[#6136]: https://github.com/ElementsProject/lightning/pull/6136
[#6128]: https://github.com/ElementsProject/lightning/pull/6128
[#6154]: https://github.com/ElementsProject/lightning/pull/6154
[#6029]: https://github.com/ElementsProject/lightning/pull/6029
[#6075]: https://github.com/ElementsProject/lightning/pull/6075
[#5708]: https://github.com/ElementsProject/lightning/pull/5708
[#6124]: https://github.com/ElementsProject/lightning/pull/6124
[#6012]: https://github.com/ElementsProject/lightning/pull/6012
[#6090]: https://github.com/ElementsProject/lightning/pull/6090
[#6142]: https://github.com/ElementsProject/lightning/pull/6142
[#6140]: https://github.com/ElementsProject/lightning/pull/6140
[#6097]: https://github.com/ElementsProject/lightning/pull/6097
[#6170]: https://github.com/ElementsProject/lightning/pull/6170
[#6107]: https://github.com/ElementsProject/lightning/pull/6107
[#6110]: https://github.com/ElementsProject/lightning/pull/6110
[#6073]: https://github.com/ElementsProject/lightning/pull/6073
[#6115]: https://github.com/ElementsProject/lightning/pull/6115
[#6109]: https://github.com/ElementsProject/lightning/pull/6109
[#6158]: https://github.com/ElementsProject/lightning/pull/6158
[#6184]: https://github.com/ElementsProject/lightning/pull/6184
[#6229]: https://github.com/ElementsProject/lightning/pull/6229


## [23.02.2] - 2023-03-14: "CBDC Backing Layer III"


### Added

 - JSON-RPC: Restore `pay` for a bolt11 which uses a `description_hash`, without setting `description` (still deprecated, but the world is not ready) [

[#6092]: https://github.com/ElementsProject/lightning/pull/6092


## [23.02.1] - 2023-03-10: "CBDC Backing Layer II"

This release named by @whitslack

### Added


### Changed

 - gossipd: Revert zombification change, keep all gossip for now. ([#6069])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.


### Removed


### Fixed

 - Plugins: `sql` nodes table now gets refreshed when gossip changes. ([#6068])
 - connectd: Fixed a crash on new connections. ([#6070])
 - wallet: Don't crash on broken database migrations. ([#6071])


### EXPERIMENTAL

 - `experimental-peer-storage`: only send to peers which support it. ([#6072])


[#6068]: https://github.com/ElementsProject/lightning/pull/6068
[#6069]: https://github.com/ElementsProject/lightning/pull/6069
[#6070]: https://github.com/ElementsProject/lightning/pull/6070
[#6071]: https://github.com/ElementsProject/lightning/pull/6071
[#6072]: https://github.com/ElementsProject/lightning/pull/6072


## [23.02] - 2023-03-01: "CBDC Backing Layer"

This release named by @whitslack

NOTE 1: This release contains breaking protocol changes to dual-funding and
        offers, making them incompatible with previous releases.
NOTE 2: Periodic pruning of channels now keeps track of them as 'zombies.' This
        behavior is in line with the lightning specification but results in
        fewer nodes and channels listed by `listnodes`/`listpeers`. These
        channels will resume as soon as the missing side broadcasts a recent
        channel update.


### Added

 - Plugins: `sql` plugin command to perform server-side complex queries. ([#5679])
 - JSON-RPC: `preapprovekeysend`: New command to preapprove payment details with an HSM. ([#5821])
 - JSON-RPC: `preapproveinvoice`: New command to preapprove a BOLT11 invoice with an HSM. ([#5821])
 - JSON-RPC: `listpeerchannels`: New command to return information on direct channels with our peers. ([#5825])
 - JSON-RPC: `signinvoice`: New command to sign a BOLT11 invoice. ([#5697])
 - JSON-RPC: `upgradewallet`: New command to sweep all p2sh-wrapped outputs to a native segwit output. ([#5670])
 - JSON-RPC: `fundpsbt` option `nonwrapped` filters out p2sh wrapped inputs. ([#5670])
 - JSON-RPC: `listpeers` output now has `num_channels` as `channels` is deprecated (see `listpeerchannels`). ([#5968])
 - JSON-RPC: `listchannels` added a `direction` field (0 or 1) as per gossip specification. ([#5679])
 - cli: `--commando=peerid:rune` (or `-c peerid:rune`) as convenient shortcut for running commando commands. ([#5866])
 - Plugins: `commando` now supports `filter` as a parameter (for send and receive). ([#5866])
 - Config: Added config option `announce-addr-discovered-port` to set custom port for IP discovery. ([#5842])
 - Config: Added config switch `announce-addr-discovered`: on/off/auto ([#5841])
 - doc: we now annotate what versions JSON field additions and deprecations happenened. ([#5867])
 - SECURITY.md: Where to send sensitive bug reports, and dev GPG fingerprints. ([#5960])


### Changed

 - JSON-RPC: `sendcustommsg` can now be called by a plugin from within the `peer_connected` hook. ([#5361])
 - JSON-RPC: `getinfo` `address` array is always present (though may be empty.) ([#5904])
 - postgres: Ordering of HTLCs in `listhtlcs` are now ordered by time of creation. ([#5863])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - Config: The --disable-ip-discovery config switch: use `announce-addr-discovered`. ([#5841])
 - JSON-RPC: `newaddr`: `addresstype` `p2sh-segwit` (use default, or `bech32`.) ([#5751])
 - JSON-RPC: `listpeers` `channels` array: use `listpeerchannels`. ([#5825])
 - plugins: `commando` JSON commands without an `id` (see doc/lightningd-rpc.7.md for how to construct a good id field). ([#5866])


### Removed

 - JSON-RPC: `sendpay` `route` argument `style` "legacy" (deprecated v0.11.0) ([#5747])
 - JSON-RPC: `close` `destination` no longer allows p2pkh or p2sh addresses. (deprecated v0.11.0) ([#5747])
 - JSON-RPC: `fundpsbt`/`utxopsbt` `reserve` must be a number, not bool. (deprecated v0.11.0) ([#5747])
 - JSON-RPC: `invoice` `expiry` no longer allowed to be a string with suffix, use an integer number of seconds. (deprecated v0.11.0) ([#5747])
 - JSON-RPC: `pay` for a bolt11 which uses a `description_hash`, without setting `description`. (deprecated v0.11.0) ([#5747])


### Fixed

 - gossip: We removed a warning for old `node_announcement` that was causing LND peers to disconnect ([#5925])
 - gossip: We removed a warning for malformed `channel_update` that was causing LND peers to disconnect  ([#5897])
 - cli: accepts long paths as options ([#5883])
 - JSON-RPC: `getinfo` `blockheight` no longer sits on 0 while we sync with bitcoind the first time. ([#5963])
 - keysend: Keysend would strip even allowed extra TLV types before resolving, this is no longer the case. ([#6031])
 - lightningd: we no longer stack multiple reconnection attempts if connections fail. ([#5946])
 - Plugins: `pay` uses the correct local channel for payments when there are multiple available (not just always the first!) ([#5947])
 - Pruned channels are more reliably restored. ([#5839])
 - `delpay`: Actually delete the specified payment (mainly found by `autoclean`). ([#6043])
 - pay: Don't assert() on malformed BOLT11 strings. ([#5891])
 - gossmap: Fixed `FATAL SIGNAL 11` on gossmap node announcement parsing. ([#6005])
 - channeld no longer retains dead HTLCs in memory. ([#5882])
 - database: Correctly identity official release versions for database upgrade. ([#5880])
 - Plugins: `commando` now responds to remote JSON calls with the correct JSON `id` field. ([#5866])
 - JSON-RPC: `datastore` handles escapes in `string` parameter correctly. ([#5994])
 - JSON-RPC: `sendpay` now can send to a short-channel-id alias for the first hop. ([#5846])
 - topology: Fixed memleak in `listchannels` ([#5865])


### EXPERIMENTAL

 - Protocol: Peer Storage: Distribute your encrypted backup to your peers, which can be retrieved to recover funds upon complete dataloss. ([#5361])
 - Protocol: `offers` breaking blinded payments change (total_amount_sat required, update_add_tlvs fix, Eclair compat.) ([#5892])
 - Protocol: Dual-funding spec changed in incompatible ways, won't work with old versions (but maybe soon with Eclair!!) ([#5956])
 - Experimental-Dual-Fund: Open failures don't disconnect, but instead fail the opening process. ([#5767])
 - JSON-RPC: `listtransactions` `channel` and `type` field removed at top level. ([#5679])


[#5825]: https://github.com/ElementsProject/lightning/pull/5825
[#5882]: https://github.com/ElementsProject/lightning/pull/5882
[#5839]: https://github.com/ElementsProject/lightning/pull/5839
[#5892]: https://github.com/ElementsProject/lightning/pull/5892
[#5751]: https://github.com/ElementsProject/lightning/pull/5751
[#5963]: https://github.com/ElementsProject/lightning/pull/5963
[#5891]: https://github.com/ElementsProject/lightning/pull/5891
[#5747]: https://github.com/ElementsProject/lightning/pull/5747
[#5670]: https://github.com/ElementsProject/lightning/pull/5670
[#5846]: https://github.com/ElementsProject/lightning/pull/5846
[#5880]: https://github.com/ElementsProject/lightning/pull/5880
[#5866]: https://github.com/ElementsProject/lightning/pull/5866
[#5697]: https://github.com/ElementsProject/lightning/pull/5697
[#5867]: https://github.com/ElementsProject/lightning/pull/5867
[#5883]: https://github.com/ElementsProject/lightning/pull/5883
[#5960]: https://github.com/ElementsProject/lightning/pull/5960
[#5679]: https://github.com/ElementsProject/lightning/pull/5679
[#5821]: https://github.com/ElementsProject/lightning/pull/5821
[#5946]: https://github.com/ElementsProject/lightning/pull/5946
[#5968]: https://github.com/ElementsProject/lightning/pull/5968
[#5947]: https://github.com/ElementsProject/lightning/pull/5947
[#5863]: https://github.com/ElementsProject/lightning/pull/5863
[#5925]: https://github.com/ElementsProject/lightning/pull/5925
[#5361]: https://github.com/ElementsProject/lightning/pull/5361
[#5767]: https://github.com/ElementsProject/lightning/pull/5767
[#5841]: https://github.com/ElementsProject/lightning/pull/5841
[#5865]: https://github.com/ElementsProject/lightning/pull/5865
[#5842]: https://github.com/ElementsProject/lightning/pull/5842
[#5956]: https://github.com/ElementsProject/lightning/pull/5956
[#5897]: https://github.com/ElementsProject/lightning/pull/5897
[#5904]: https://github.com/ElementsProject/lightning/pull/5904
[#5994]: https://github.com/ElementsProject/lightning/pull/5994
[#6005]: https://github.com/ElementsProject/lightning/pull/6005


## [22.11.1] - 2022-12-09: "Alameda Yield Generator II"

### Added

 - JSON-RPC: reverts requirement for "jsonrpc" "2.0" inside requests (still deprecated though, just for a while longer!) ([#5783])

### Changed

 - config: `announce-addr-dns` needs to be set to *true* to put DNS names into node announcements, otherwise they are suppressed.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - config: `announce-addr-dns` (currently defaults to `false`).  This will default to `true` once enough of the network has upgraded to understand DNS entries. ([#5796])

### Fixed

 - Build: arm32 compiler error in fetchinvoice, due to bad types on 32-bit platforms. ([#5785])
 - JSON-RPC: `autoclean-once` response `uncleaned` count is now correct. ([#5775])
 - Plugin: `autoclean` could misperform or get killed due to lightningd's invalid handling of JSON batching. ([#5775])
 - reckless verbosity properly applied. ([#5781])
 - wireaddr: #5657 allow '_' underscore in hostname part of DNS FQDN ([#5789])

[#5781]: https://github.com/ElementsProject/lightning/pull/5781
[#5783]: https://github.com/ElementsProject/lightning/pull/5783
[#5775]: https://github.com/ElementsProject/lightning/pull/5775
[#5789]: https://github.com/ElementsProject/lightning/pull/5789
[#5796]: https://github.com/ElementsProject/lightning/pull/5796
[#5785]: https://github.com/ElementsProject/lightning/pull/5785
[#5775]: https://github.com/ElementsProject/lightning/pull/5775
[22.11.1]: https://github.com/ElementsProject/lightning/releases/tag/v22.11.1


## [22.11] - 2022-11-30: "Alameda Yield Generator"


This release named by @endothermicdev.
### Added

 - Reckless - a Core Lightning plugin manager ([#5647])
 - Config: `--database-upgrade=true` required if a non-release version wants to (irrevocably!) upgrade the db. ([#5550])
 - Documentation: `lightningd-rpc` manual page describes details of our JSON-RPC interface, including compatibility and filtering. ([#5681])
 - JSON-RPC: `filter` object allows reduction of JSON response to (most) commands. ([#5681])
 - cli: new `--filter` parameter to reduce JSON output. ([#5681])
 - pyln: LightningRpc has new `reply_filter` context manager for reducing output of RPC commands. ([#5681])
 - JSON-RPC: `listhtlcs` new command to list all known HTLCS. ([#5594])
 - Plugins: `autoclean` can now delete old forwards, payments, and invoices automatically. ([#5594])
 - Plugins: `autoclean-once` command for a single cleanup. ([#5594])
 - Plugins: `autoclean-status` command to see what autoclean is doing. ([#5594])
 - Config: `accept-htlc-tlv-types` lets us accept unknown even HTLC TLV fields we would normally reject on parsing (was EXPERIMENTAL-only `experimental-accept-extra-tlv-types`). ([#5619])
 - JSON-RPC: The `extratlvs` argument for `keysend` now allows quoting the type numbers in string ([#5674])
 - JSON-RPC: `batching` command to allow database transactions to cross multiple back-to-back JSON commands. ([#5594])
 - JSON-RPC: `channel_opened` notification `channel_ready` flag. ([#5490])
 - JSON-RPC: `delforward` command to delete listforwards entries. ([#5594])
 - JSON-RPC: `delpay` takes optional `groupid` and `partid` parameters to specify exactly what payment to delete. ([#5594])
 - JSON-RPC: `fundchannel`, `multifundchannel` and `fundchannel_start` now accept a `reserve` parameter to indicate the absolute reserve to impose on the peer. ([#5315])
 - Plugins: `keysend` will now attach the longest valid text field in the onion to the invoice (so you can have Sphinx.chat users spam you!) ([#5619])
 - JSON-RPC: `keysend` now has `extratlvs` option in non-EXPERIMENTAL builds. ([#5619])
 - JSON-RPC: `listforwards` now shows `in_htlc_id` and `out_htlc_id` ([#5594])
 - JSON-RPC: `makesecret` can take a string argument instead of hex. ([#5633])
 - JSON-RPC: `pay` and `listpays` now lists the completion time. ([#5398])
 - Plugins: Added notification topic "block_processed". ([#5581])
 - Plugins: `keysend` now exposes the `extratlvs` field ([#5674])
 - Plugins: The `openchannel` hook may return a custom absolute `reserve` value that the peer must not dip below. ([#5315])
 - Plugins: `getmanfest` response can contain `nonnumericids` to indicate support for modern string-based JSON request ids. ([#5727])
 - Protocol: We now delay forgetting funding-spent channels for 12 blocks (as per latest BOLTs, to support splicing in future). ([#5592])
 - Protocol: We now set the `dont_forward` bit on private channel_update's message_flags (as per latest BOLTs). ([#5592])
 - cln-plugin: Options are no longer required to have a default value ([#5369])


### Changed

 - Protocol: We now require all channel_update messages include htlc_maximum_msat (as per latest BOLTs) ([#5592])
 - Protocol: Bolt7 #911 DNS annoucenent support is no longer EXPERIMENTAL ([#5487])
 - JSON-RPC: `listfunds` now lists coinbase outputs as 'immature' until they're spendable ([#5664])
 - JSON-RPC: UTXOs aren't spendable while immature ([#5664])
 - Plugins: `openchannel2` now always includes the `channel_max_msat` ([#5650])
 - JSON-RPC: `createonion` no longer allows non-TLV-style payloads. ([#5639])
 - cln-plugin: Moved the state binding to the plugin until after the configuration step ([#5493])
 - pyln-spec: package updated to latest spec version. ([#5621])
 - JSON-RPC: `listforwards` now never shows `payment_hash`; use `listhtlcs`. ([#5594])
 - cln-rpc: The `wrong_funding` argument for `close` was changed from `bytes` to `outpoint` ([#5444])
 - JSON-RPC: Error code from bcli plugin changed from 400 to 500. ([#5596])
 - Plugins: `balance_snapshot` notification does not send balances for channels that aren't locked-in/opened yet ([#5587])
 - Plugins: RPC operations are now still available during shutdown. ([#5577])
 - JSON-RPC: `listpeers` `status` now refers to "channel ready" rather than "funding locked" (BOLT language change for zeroconf channels) ([#5490])
 - Protocol: `funding_locked` is now called `channel_ready` as per latest BOLTs. ([#5490])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON-RPC: `autocleaninvoice` (use option `autoclean-expiredinvoices-age`) ([#5594])
 - JSON-RPC: `delexpiredinvoice`: use `autoclean-once`. ([#5594])
 - JSON-RPC: `commando-rune` restrictions is always an array, each element an array of alternatives.  Replaces a string with `|`-separators, so no escaping necessary except for `\\`. ([#5539])
 - JSON-RPC: `channel_opened` notification `funding_locked` flag (use `channel_ready`: BOLTs namechange). ([#5490])
 - Plugins: numeric JSON request ids: modern ones will be strings (see doc/lightningd-rpc.7.md!) ([#5727])


### Removed

 - Protocol: we no longer forward HTLCs with legacy onions. ([#5639])
 - `hsmtool`: hsm_secret (ignored) on cmdline for dumponchaindescriptors (deprecated in v0.9.3) ([#5490])
 - Plugins: plugin init `use_proxy_always` (deprecated v0.10.2) ([#5490])
 - JSON-RPC: plugins must supply `usage` parameter (deprecated v0.7) ([#5490])
 - Old order of the `status` parameter in the `listforwards` rpc command (deprecated in v0.10.2) ([#5490])
 - JSONRPC: RPC framework now requires the `"jsonrpc"` property inside the request (deprecated in v0.10.2) ([#5490])
 - JSON API: Removed double wrapping of `rpc_command` payload in `rpc_command` JSON field (deprecated v0.8.2) ([#5490])


### Fixed

 - plugins: `pay` now knows it can use locally-connected wumbo channels for large payments. ([#5746])
 - lightningd: do not abort while parsing hsm pwd ([#5725])
 - plugins: on large/slow nodes we could blame plugins for failing to answer init in time, when we were just slow. ([#5741])
 - ld: Reduce identification of own transactions to not slow down over time, reducing block processing time ([#5715])
 - Fixed gossip_store corruption from duplicate private channel updates ([#5661])
 - Fixed a condition for newly created channels that could trigger a need for reconnect. ([#5601])
 - proper gossip_store operation may resolve some previous gossip propagation issues ([#5591])
 - onchaind: Witness weight estimations could be slightly lower than the VLS signer ([#5669])
 - Protocol: we now correctly decrypt non-256-length onion errors (we always forwarded them fine, now we actually can parse them). ([#5698])
 - devtools: `mkfunding` command no longer crashes (abort) ([#5677])
 - plugins: on large/slow nodes we could blame plugins for failing to answer init in time, when we were just slow. ([#5741])
 - Plugins: `funder` now honors lease requests across RBFs ([#5650])
 - Plugins: `keysend` now removes unknown even (technically illegal!) fields, to try to accept more payments. ([#5645])
 - channeld: Channel reinitialization no longer fails when the number of outstanding outgoing HTLCs exceeds `max_accepted_htlcs`. ([#5640])
 - pay: Squeezed out the last `msat` from our local view of the network ([#5315])
 - peer_control: getinfo shows the correct port on discovered IPs ([#5585])
 - bcli: don't expose bitcoin RPC password on commandline ([#5509])
 - Plugins: topology plugin could crash when it sees duplicate private channel announcements. ([#5593])
 - JSON-RPC: `commando-rune` now handles \\ escapes properly. ([#5539])
 - peer_control: getinfo showing unannounced addresses. ([#5584])


### EXPERIMENTAL

 - JSON-RPC: `pay` and `sendpay` `localofferid` is now `localinvreqid`. ([#5676])
 - Protocol: Support for forwarding blinded payments (as per latest draft) ([#5646])
 - offers: complete rework of spec from other teams (yay!) breaks previous compatibility (boo!) ([#5646])
 - offers: old `payer_key` proofs won't work. ([#5646])
 - bolt12: remove "vendor" (use "issuer") and "timestamp" (use "created_at") fields (deprecated v0.10.2). ([#5490])



[#5315]: https://github.com/ElementsProject/lightning/pull/5315
[#5664]: https://github.com/ElementsProject/lightning/pull/5664
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5640]: https://github.com/ElementsProject/lightning/pull/5640
[#5398]: https://github.com/ElementsProject/lightning/pull/5398
[#5585]: https://github.com/ElementsProject/lightning/pull/5585
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5587]: https://github.com/ElementsProject/lightning/pull/5587
[#5584]: https://github.com/ElementsProject/lightning/pull/5584
[#5674]: https://github.com/ElementsProject/lightning/pull/5674
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5601]: https://github.com/ElementsProject/lightning/pull/5601
[#5315]: https://github.com/ElementsProject/lightning/pull/5315
[#5669]: https://github.com/ElementsProject/lightning/pull/5669
[#5681]: https://github.com/ElementsProject/lightning/pull/5681
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5619]: https://github.com/ElementsProject/lightning/pull/5619
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5645]: https://github.com/ElementsProject/lightning/pull/5645
[#5619]: https://github.com/ElementsProject/lightning/pull/5619
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5539]: https://github.com/ElementsProject/lightning/pull/5539
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5646]: https://github.com/ElementsProject/lightning/pull/5646
[#5596]: https://github.com/ElementsProject/lightning/pull/5596
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5677]: https://github.com/ElementsProject/lightning/pull/5677
[#5287]: https://github.com/ElementsProject/lightning/pull/5287
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5315]: https://github.com/ElementsProject/lightning/pull/5315
[#5539]: https://github.com/ElementsProject/lightning/pull/5539
[#5592]: https://github.com/ElementsProject/lightning/pull/5592
[#5741]: https://github.com/ElementsProject/lightning/pull/5741
[#5746]: https://github.com/ElementsProject/lightning/pull/5746
[#5647]: https://github.com/ElementsProject/lightning/pull/5647
[#5577]: https://github.com/ElementsProject/lightning/pull/5577
[#5639]: https://github.com/ElementsProject/lightning/pull/5639
[#5621]: https://github.com/ElementsProject/lightning/pull/5621
[#5581]: https://github.com/ElementsProject/lightning/pull/5581
[#5369]: https://github.com/ElementsProject/lightning/pull/5369
[#5727]: https://github.com/ElementsProject/lightning/pull/5727
[#5592]: https://github.com/ElementsProject/lightning/pull/5592
[#5487]: https://github.com/ElementsProject/lightning/pull/5487
[#5509]: https://github.com/ElementsProject/lightning/pull/5509
[#5676]: https://github.com/ElementsProject/lightning/pull/5676
[#5664]: https://github.com/ElementsProject/lightning/pull/5664
[#5715]: https://github.com/ElementsProject/lightning/pull/5715
[#5681]: https://github.com/ElementsProject/lightning/pull/5681
[#5727]: https://github.com/ElementsProject/lightning/pull/5727
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5681]: https://github.com/ElementsProject/lightning/pull/5681
[#5698]: https://github.com/ElementsProject/lightning/pull/5698
[#5619]: https://github.com/ElementsProject/lightning/pull/5619
[#5493]: https://github.com/ElementsProject/lightning/pull/5493
[#5633]: https://github.com/ElementsProject/lightning/pull/5633
[#5646]: https://github.com/ElementsProject/lightning/pull/5646
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5646]: https://github.com/ElementsProject/lightning/pull/5646
[#5593]: https://github.com/ElementsProject/lightning/pull/5593
[#5674]: https://github.com/ElementsProject/lightning/pull/5674
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5650]: https://github.com/ElementsProject/lightning/pull/5650
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5592]: https://github.com/ElementsProject/lightning/pull/5592
[#5639]: https://github.com/ElementsProject/lightning/pull/5639
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5550]: https://github.com/ElementsProject/lightning/pull/5550
[#5490]: https://github.com/ElementsProject/lightning/pull/5490
[#5725]: https://github.com/ElementsProject/lightning/pull/5725
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5444]: https://github.com/ElementsProject/lightning/pull/5444
[#5650]: https://github.com/ElementsProject/lightning/pull/5650
[#5594]: https://github.com/ElementsProject/lightning/pull/5594
[#5661]: https://github.com/ElementsProject/lightning/pull/5661
[#5681]: https://github.com/ElementsProject/lightning/pull/5681
[#5591]: https://github.com/ElementsProject/lightning/pull/5591
[22.11]: https://github.com/ElementsProject/lightning/releases/tag/v22.11


## [0.12.1] - 2022-09-13: Web-8 init (dot one)

Point release with some bugfixes and patches.

### Removed

- build: `mrkd` and `mistune` not required to build project

### Fixed

- lnprototest: builds for lnprototest tests now use 22.04 LTS, which fixes a problem with loading `mako`. ([#5583])
- Plugins: topology plugin could crash when it sees duplicate private channel announcements ([#5593])
- connectd: proper `gossip_store` operation may resolve some previous gossip propagation issues and connectd crashes ([#5591])
- connectd: Fixed a condition for newly created channels that could trigger a need for reconnect. ([#5601])
- `peer_control`: getinfo showing unannounced addresses. ([#5584])
- `peer_control`: getinfo shows the correct port on discovered IPs ([#5585])


[#5583]: https://github.com/ElementsProject/lightning/pull/5583
[#5584]: https://github.com/ElementsProject/lightning/pull/5584
[#5593]: https://github.com/ElementsProject/lightning/pull/5593
[#5591]: https://github.com/ElementsProject/lightning/pull/5591


## [0.12.0] - 2022-08-23: Web-8 init

This release named by @adi2011.

Developers please note the Great Msat Migration has begun:
1. All JSON amount field names now end in "_msat" (others are deprecated)
2. Their values are strings ending in "msat", but will soon be normal integers.
3. You should accept both: set `allow-deprecated-apis=false` to test!

### Added

 - *NEW*: `commando` a new builtin plugin to send/recv peer commands over the lightning network, using runes. ([#5370])
 - *NEW*: New built-in plugin `bookkeeper` w/ commands `bkpr-listaccountevents`, `bkpr-listbalances`, `bkpr-listincome`, `bkpr-channelsapy`, `bkpr-dumpincomecsv`, `bkpr-inspect` ([#5071])
 - *NEW*: Emergency channel backup ("static backup") which allows us to seek fund recovery from honest peers in case of complete data loss ([#5422])
 - Config: `log-level=debug:<partial-nodeid>` supported to get debug-level logs for everything about a peer. ([#5349])
 - JSON-RPC: `connect` use the standard port derivation when the port is not specified. ([#5242])
 - JSON-RPC: `fetchinvoice` `changes` `amount_msat` ([#5306])
 - JSON-RPC: Added `mindepth` argument to specify the number of confirmations we require for `fundchannel` and `multifundchannel` ([#5275])
 - JSON-RPC: `listpeers` new fields for `funding` (`remote_funds_msat`, `local_funds_msat`, `fee_paid_msat`, `fee_rcvd_msat`). ([#5477])
 - JSON-RPC: `listpeers` add optional `remote_addr` ([#5244])
 - JSON-RPC: `listforwards` now shows `out_channel` in more cases: even if it couldn't actually send to it. ([#5330])
 - JSON-RPC: `pay` `attempts` `amount_msat` field. ([#5306])
 - Protocol: private channels will only route using short-channel-ids if channel opened with option_scid_alias-supporting peer. ([#5501])
 - Protocol: invoice routehints will use fake short-channel-ids for private channels if channel opened with option_scid_alias-supporting peer. ([#5501])
 - Protocol: we now advertize the `option_channel_type` feature (which we actually supported since v0.10.2) ([#5455])
 - Plugins: `channel_state_changed` now triggers for a v1 channel's initial "CHANNELD_AWAITING_LOCKIN" state transition (from prior state "unknown") ([#5381])
 - Plugins: `htlc_accepted_hook` `amount_msat` field. ([#5306])
 - Plugins: `htlc_accepted` now exposes the `short_channel_id` for the channel from which that HTLC is coming from and the low-level per-channel HTLC `id`, which are necessary for bridging two different Lightning Networks when MPP is involved. ([#5303])
 - Plugins: The `openchannel` hook may return a `mindepth` indicating how many confirmations are required. ([#5275])
 - msggen: introduce chain of responsibility pattern to make msggen extensible ([#5216])
 - cln_plugin: persist cln configuration from init msg ([#5279])
 - pyln-testing: Added utilities to read and parse `gossip_store` file for nodes. ([#5275])
 - `hsmtool`: new command `checkhsm` to check BIP39 passphrase against hsm_secret. ([#5441])
 - contrib: Added `fund_ln` to the contrib/startup\_regtest.sh ([#5062])
 - build: Added m1 architecture support for macos ([#4988])
 - build: Reproducible builds now include rust binaries such as the `cln-grpc` plugin ([#5421])


### Changed

 - `lightningd`: will refuse to start with the wrong node_id (i.e. hsm_secret changes). ([#5425])
 - `connectd`: prefer IPv6 connections when available. ([#5244])
 - `connectd`: Only use IP discovery as fallback when no addresses would be announced ([#5344])
 - `connectd`: give busy peers more time to respond to pings. ([#5347])
 - `gossipd`: now accepts spam gossip, but squelches it for ([#5239])
 - gossip: gossip\_store updated to version 10. ([#5239])
 - Options: `log-file` option specified multiple times opens multiple log files. ([#5281])
 - JSON-RPC: `sendpay` and `sendonion` now obey the first hop "channel" short_channel_id, if specified. ([#5505])
 - JSON-RPC: `signpsbt` no longer crashes if it doesn't like what your PSBT is ([#5506])
 - JSON-RPC: `signpsbt` will now add redeemscript + witness-utxo to the PSBT for an input that we can sign for, before signing it. ([#5506])
 - JSON-RPC: `plugin start` now assumes relative path to default plugins dir if the path is not found in absolute context. i.e. lightning-cli plugin start my_plugin.py ([#5211])
 - JSON-RPC: `fundchannel`: now errors if you try to buy a liquidity ad but dont' have `experimental-dual-fund` enabled ([#5389])
 - JSON-RPC: "\_msat" fields can be raw numbers, not "123msat" strings (please handle both!) ([#5306])
 - JSON-RPC: `invoice`, `sendonion`, `sendpay`, `pay`, `keysend`, `fetchinvoice`, `sendinvoice`: `msatoshi` argument is now called `amount_msat` to match other fields. ([#5306])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON-RPC: `listpeers`.`funded` fields `local_msat` and `remote_msat`. ([#5477])
 - JSON-RPC: `listtransactions` `msat` (use `amount_msat`) ([#5306])
 - JSON-RPC: checkmessage return an error when the pubkey is not specified and it is unknown in the network graph. ([#5252])
 - JSON-RPC: "_msat" fields as "123msat" strings (will be only numbers) ([#5306])
 - JSON-RPC: `sendpay` `route` elements `msatoshi` (use `amount_msat`) ([#5306])
 - JSON-RPC: `pay`, `decode`, `decodepay`, `getroute`, `listinvoices`, `listpays` and `listsendpays` `msatoshi` fields (use `amount_msat`). ([#5306])
 - JSON-RPC: `getinfo` `msatoshi_fees_collected` field (use `fees_collected_msat`). ([#5306])
 - JSON-RPC: `listpeers` `channels`: `msatoshi_to_us`, `msatoshi_to_us_min`, `msatoshi_to_us_max`, `msatoshi_total`, `dust_limit_satoshis`, `our_channel_reserve_satoshis`, `their_channel_reserve_satoshis`, `spendable_msatoshi`, `receivable_msatoshi`, `in_msatoshi_offered`, `in_msatoshi_fulfilled`, `out_msatoshi_offered`, `out_msatoshi_fulfilled`, `max_htlc_value_in_flight_msat` and `htlc_minimum_msat` (use `to_us_msat`, `min_to_us_msat`, `max_to_us_msat`, `total_msat`, `dust_limit_msat`, `our_reserve_msat`, `their_reserve_msat`, `spendable_msat`, `receivable_msat`, `in_offered_msat`, `in_fulfilled_msat`, `out_offered_msat`, `out_fulfilled_msat`, `max_total_htlc_in_msat` and `minimum_htlc_in_msat`). ([#5306])
 - JSON-RPC: `listinvoices` and `pay` `msatoshi_received` and `msatoshi_sent` (use `amount_received_msat`, `amount_sent_msat`) ([#5306])
 - JSON-RPC: `listpays` and `listsendpays` `msatoshi_sent` (use `amount_sent_msat`) ([#5306])
 - JSON-RPC: `listforwards` `in_msatoshi`, `out_msatoshi` and `fee` (use `in_msat`, `out_msat` and `fee_msat`) ([#5306])
 - JSON-RPC: `listfunds` `outputs` `value` (use `amount_msat`) ([#5306])
 - JSON-RPC: `fetchinvoice` `changes` `msat` (use `amount_msat`) ([#5306])
 - JSON-RPC: `pay` `attempts` `amount` field (use `amount_msat`). ([#5306])
 - JSON-RPC: `invoice`, `sendonion`, `sendpay`, `pay`, `keysend`, `fetchinvoice`, `sendinvoice` `msatoshi` (use `amount_msat`) ([#5306])
 - `listconfigs` `plugins` `options` which are not set are omitted, not `null`. ([#5306])
 - Plugins: `htlc_accepted_hook` `amount` field (use `amount_msat`) ([#5306])
 - Plugins: `coin_movement` notification: `balance`, `credit`, `debit` and `fees` (use `balance_msat`, `credit_msat`, `debit_msat` and `fees_msat`) ([#5306])
 - Plugins: `rbf_channel` and `openchannel2` hooks `their_funding` (use `their_funding_msat`) ([#5306])
 - Plugins: `openchannel2` hook `dust_limit_satoshis` (use `dust_limit_msat`) ([#5306])
 - Plugins: `openchannel` hook `funding_satoshis` (use `funding_msat`) ([#5306])
 - Plugins: `openchannel` hook `dust_limit_satoshis` (use `dust_limit_msat`) ([#5306])
 - Plugins: `openchannel` hook `channel_reserve_satoshis` (use `channel_reserve_msat`) ([#5306])
 - Plugins: `channel_opened` notification `amount` (use `funding_msat`) ([#5306])
 - Plugins: `htlc_accepted` `forward_amount` (use `forward_msat`) ([#5306])


### Removed

 - Protocol: We no longer create gossip messages which use zlib encoding (we still understand them, for now!) ([#5226])
 - JSON-RPC: `getsharedsecret` API: use `makesecret` ([#5430])
 - JSON-RPC: removed `listtransactions` `outputs` `satoshis` field (deprecated v0.10.1) ([#5264])
 - JSON-RPC: removed `listpeers` `channels` deprecated fields (deprecated v0.10.1) ([#5264])
 - JSON-RPC: removed `listpeers` `channels` `closer` now omitted, rather than `null` (deprecated v0.10.1) ([#5264])
 - libhsmd: Removed the `libhsmd_python` wrapper as it was unused ([#5415])
 - Options: removed `enable-autotor-v2-mode` option (deprecated v0.10.1) ([#5264])


### Fixed

 - db: postgresql crash on startup when dual-funding lease open is pending with "s32 field doesn't match size: expected 4, actual 8" ([#5513])
 - `connectd`: various crashes and issues fixed by simplification and rewrite. ([#5261])
 - `connectd`: Port of a DNS announcement can be 0 if unspecified ([#5434])
 - `dualopend`: Issue if the number of outputs decreases in a dualopen RBF or splice. ([#5378])
 - `channeld`: Enforce our own `minimum_depth` beyond just confirming ([#5275])
 - logging: `log-prefix` now correctly prefixes *all* log messages. ([#5349])
 - logging: `log-level` `io` shows JSONRPC output, as well as input. ([#5306])
 - PSBT: Fix signature encoding to comply with BIP-0171. ([#5307])
 - signmessage: improve the UX of the rpc command when zbase is not a valid one ([#5297])
 - JSON-RPC: Adds dynamically detected public IP addresses to `getinfo` ([#5244])
 - cln-rpc: naming mismatch for `ConnectPeer` causing `connectpeer` to be called on the JSON-RPC ([#5362])
 - pyln-spec: update the bolts implementation ([#5168])
 - Plugins: setting the default value of a parameter to `null` is the same as not setting it (pyln plugins did this!). ([#5460])
 - Plugins: plugins would hang indefinitely despite `lightningd` closing the connection ([#5362])
 - Plugins: `channel_opened` notification `funding_locked` field is now accurate: was always `true`. ([#5489])
 - Upgrade docker base image from Debian buster to bullseye to work with glibc 2.29+ #5276 ([#5278])
 - docker: The docker images are now built with the rust plugins `cln-grpc` ([#5270])

[#4988]: https://github.com/ElementsProject/lightning/pull/4988
[#5062]: https://github.com/ElementsProject/lightning/pull/5062
[#5071]: https://github.com/ElementsProject/lightning/pull/5071
[#5168]: https://github.com/ElementsProject/lightning/pull/5168
[#5211]: https://github.com/ElementsProject/lightning/pull/5211
[#5216]: https://github.com/ElementsProject/lightning/pull/5216
[#5226]: https://github.com/ElementsProject/lightning/pull/5226
[#5239]: https://github.com/ElementsProject/lightning/pull/5239
[#5242]: https://github.com/ElementsProject/lightning/pull/5242
[#5244]: https://github.com/ElementsProject/lightning/pull/5244
[#5252]: https://github.com/ElementsProject/lightning/pull/5252
[#5261]: https://github.com/ElementsProject/lightning/pull/5261
[#5264]: https://github.com/ElementsProject/lightning/pull/5264
[#5270]: https://github.com/ElementsProject/lightning/pull/5270
[#5275]: https://github.com/ElementsProject/lightning/pull/5275
[#5278]: https://github.com/ElementsProject/lightning/pull/5278
[#5279]: https://github.com/ElementsProject/lightning/pull/5279
[#5281]: https://github.com/ElementsProject/lightning/pull/5281
[#5297]: https://github.com/ElementsProject/lightning/pull/5297
[#5303]: https://github.com/ElementsProject/lightning/pull/5303
[#5306]: https://github.com/ElementsProject/lightning/pull/5306
[#5307]: https://github.com/ElementsProject/lightning/pull/5307
[#5330]: https://github.com/ElementsProject/lightning/pull/5330
[#5344]: https://github.com/ElementsProject/lightning/pull/5344
[#5347]: https://github.com/ElementsProject/lightning/pull/5347
[#5349]: https://github.com/ElementsProject/lightning/pull/5349
[#5362]: https://github.com/ElementsProject/lightning/pull/5362
[#5370]: https://github.com/ElementsProject/lightning/pull/5370
[#5378]: https://github.com/ElementsProject/lightning/pull/5378
[#5381]: https://github.com/ElementsProject/lightning/pull/5381
[#5389]: https://github.com/ElementsProject/lightning/pull/5389
[#5415]: https://github.com/ElementsProject/lightning/pull/5415
[#5421]: https://github.com/ElementsProject/lightning/pull/5421
[#5422]: https://github.com/ElementsProject/lightning/pull/5422
[#5425]: https://github.com/ElementsProject/lightning/pull/5425
[#5430]: https://github.com/ElementsProject/lightning/pull/5430
[#5434]: https://github.com/ElementsProject/lightning/pull/5434
[#5441]: https://github.com/ElementsProject/lightning/pull/5441
[#5455]: https://github.com/ElementsProject/lightning/pull/5455
[#5460]: https://github.com/ElementsProject/lightning/pull/5460
[#5475]: https://github.com/ElementsProject/lightning/pull/5475
[#5477]: https://github.com/ElementsProject/lightning/pull/5477
[#5489]: https://github.com/ElementsProject/lightning/pull/5489
[#5501]: https://github.com/ElementsProject/lightning/pull/5501
[#5505]: https://github.com/ElementsProject/lightning/pull/5505
[#5506]: https://github.com/ElementsProject/lightning/pull/5506
[#5513]: https://github.com/ElementsProject/lightning/pull/5513



## [0.11.2] - 2022-06-24: Simon's Carefully Chosen Release Name III

Regressions since 0.10.2 which could not wait for the 0.12 release,
which especially hurt larger nodes.

### Fixed

 - Protocol: treat LND "internal error" as warnings, not force close events (like v0.10) ([#5326])
 - connectd: no longer occasional crashes when peers reconnect. ([#5300])
 - connectd: another crash fix on trying to reconnect to disconnecting peer. ([#5340])
 - topology: Under some circumstances we were considering the limits on the wrong direction for a channel ([#5286])
 - routing: Fixed an issue where we would exclude the entire channel if either direction was disabled, or we hadn't seen an update yet. ([#5286])
 - connectd: large memory usage with many peers fixed. ([#5312])
 - connectd: reduce initial CPU load when connecting to peers. ([#5328])
 - lightnind: fix failed startup "Could not load channels from the database" if old TORv2 addresses were present. ([#5331])

[#5286]: https://github.com/ElementsProject/lightning/pull/5286
[#5300]: https://github.com/ElementsProject/lightning/pull/5300
[#5312]: https://github.com/ElementsProject/lightning/pull/5312
[#5326]: https://github.com/ElementsProject/lightning/pull/5326
[#5328]: https://github.com/ElementsProject/lightning/pull/5328
[#5331]: https://github.com/ElementsProject/lightning/pull/5331
[#5340]: https://github.com/ElementsProject/lightning/pull/5340
[0.11.2]: https://github.com/ElementsProject/lightning/releases/tag/v0.11.2

## [0.11.1] - 2022-05-13: Simon's Carefully Chosen Release Name II

Single change which fixed a bug introduced in 0.11.0 which could cause
unwanted unilateral closes (`bad reestablish revocation_number: 0 vs 3`)

### Fixed

 - connectd: make sure we don't keep stale reconnections around. ([#5256])
 - connectd: fix assert which we could trigger. ([#5256])

[#5256]: https://github.com/ElementsProject/lightning/pull/5256

## [0.11.0.1] - 2022-04-04: Simon's Carefully Chosen Release Name

This release would have been named by Simon Vrouwe, had he responded to my emails!

This marks the name change to core-lightning (#CLN).

### Added

 - Protocol: we now support opening multiple channels with the same peer. ([#5078])
 - Protocol: we send/receive IP addresses in `init`, and send updated node_announcement when two peers report the same remote_addr (`disable-ip-discovery` suppresses this announcement). ([#5052])
 - Protocol: we more aggressively send our own gossip, to improve propagation chances. ([#5200])
 - Plugins: `cln-grpc` first class GRPC interface for remotely controlling nodes over mTLS authentication; set `grpc-port` to activate ([#5013])
 - Database: With the `sqlite3://` scheme for `--wallet` option, you can now specify a second file path for real-time database backup by separating it from the main file path with a `:` character. ([#4890])
 - Protocol: `pay` (and decode, etc) supports bolt11 payment_metadata a-la https://github.com/lightning/bolts/pull/912 ([#5086])
 - JSON-RPC: `invoice` has a new parameter `deschashonly` to put hash of description in bolt11. ([#5121])
 - JSON-RPC: `pay` has new parameter `description`, will be required if bolt11 only has a hash. ([#5122])
 - JSON-RPC: `pay` has new parameter `maxfee` for setting absolute fee (instead of using `maxfeepercent` and/or `exemptfee`) ([#5122])
 - JSON-RPC: `listforwards` has new entry `style`, currently "legacy" or "tlv". ([#5146])
 - JSON-RPC: `delinvoice` has a new parameter `desconly` to remove description. ([#5121])
 - JSON-RPC: new `setchannel` command generalizes `setchannelfee`: you can now alter the `htlc_minimum_msat` and `htlc_maximum_msat` your node advertizes. ([#5103])
 - Config: `htlc-minimum-msat` and `htlc-maximum-msat` to set default values to  advertizes for new channels. ([#5136])
 - JSON-RPC: `listpeers` now includes a `pushed_msat` value. For leased channels, is the total lease_fee. ([#5043])
 - JSON-RPC: `getinfo` result now includes `our_features` (bits) for various Bolt #9 contexts ([#5047])
 - Docker build for ARM defaults to `bitcoin`, but can be overridden with the `LIGHTNINGD_NETWORK` envvar. ([#4896])
 - Developer: A new Rust library called `cln-rpc` can be used to interact with the JSON-RPC ([#5010])
 - JSON-RPC: A new `msggen` library allows easy generation of language bindings for the JSON-RPC from the JSON schemas ([#5010])
 - JSON-RPC: `listchannels` now includes the `funding_outnum` ([#5016])
 - JSON-RPC: `coin_movement` to 'external' accounts now include an 'originating_account' field ([#5019])
 - JSON-RPC: Add `exclude` option for `pay` command to manually exclude channels or nodes when finding a route. ([#4906])
 - Database: Speed up loading of pending HTLCs during startup by using a partial index. ([#4925])


### Changed

 - JSON-RPC: `close` by peer id will fail if there is more than one live channel (use `channel_id` or `short_channel_id` as id arg). ([#5078])
 - JSON_RPC: `sendcustommsg` now works with any connected peer, even when shutting down a channel. ([#4985])
 - JSON_RPC: `ping` now works with connected peers, even without a channel. ([#4985])
 - cli: Addition of HSM specific error code in lightning-cli ([#4908])
 - config: If the port is unspecified, the default port is chosen according to used network similarly to Bitcoin Core. ([#4900])
 - Plugins: `shutdown` notification is now send when lightningd is almost completely shutdown, RPC calls then fail with error code -5. ([#4897])
 - Protocol: `signet` addresses and invoices now use `tbs` instead of `tb`. ([#4929])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON-RPC: `pay` for a bolt11 which uses a `description_hash`, without setting `description`. ([#5122])
 - JSON-RPC: `invoice` `expiry` no longer allowed to be a string with suffix, use an integer number of seconds. ([#5104])
 - JSON-RPC: `fundpsbt`/`utxopsbt` `reserve` must be a number, not bool (for `true` use 72/don't specify, for `false` use 0).  Numbers have been allowed since v0.10.1. ([#5104])
 - JSON-RPC: `shutdown` no longer allows p2pkh or p2sh addresses. ([#5086])
 - JSON-RPC: `sendpay` `route` argument `style` "legacy" (don't use it at all, we ignore it now and always use "tlv" anyway). ([#5120])
 - JSON-RPC: `setchannelfee` (use `setchannel`). ([#5103])


### Removed

 - JSON-RPC: `legacypay` (`pay` replaced it in 0.9.0). ([#5122])
 - Protocol: support for legacy onion format removed, since everyone supports the new one. ([#5058])
 - Protocol: ... but we still forward legacy HTLC onions for now. ([#5146])
 - Plugins:  The `message` field on the `custommsg` hook (deprecated in v0.10.0) ([#4902])
 - JSON-RPC: `fundchannel_complete` `txid` and `txout` parameters (deprecated in v0.10.0) ([#4902])


### Fixed

 - onchaind: we sometimes failed to close upstream htlcs if more than one HTLC is in flight during unilateral close. ([#5130])
 - JSON-RPC: `listpays` always includes `bolt11` or `bolt12` field. ([#5122])
 - cli: don't ask to confirm the password if the `hsm_secret` is already encrypted. ([#5085])
 - cli: check if the `hsm_secret` password and the confirmation match from the command line ([#5085])
 - JSON-RPC: `connect` notification now called even if we already have a live channel. ([#5078])
 - docker: The docker image is now built with postgresql support ([#5081])
 - hsmd: Fixed a significant memory leak ([#5051])
 - closingd: more accurate weight estimation helps mutual closing near min/max feerates. ([#5004])
 - Protocol: Always flush sockets to increase chance that final message get to peer (esp. error packets). ([#4984])
 - JSON-RPC: listincoming showed incoming_capacity_msat field 1000 times actual value. ([#4913])
 - Options: Respect --always-use-proxy AND --disable-dns when parsing wireaddresses to listen on. ([#4829])
 - lightningd: remove slow memory leak in DEVELOPER builds. ([#4931])
 - JSON-RPC: `paystatus` entries no longer have two identical `amount_msat` entries. ([#4911])
 - We really do allow providing multiple addresses of the same type. ([#4902])


### EXPERIMENTAL

 - Fixed `experimental-websocket` intermittent read errors ([#5090])
 - Fixed `experimental-websocket-port` not to leave zombie processes. ([#5101])
 - Config option `--lease-fee-base-msat` renamed to `--lease-fee-base-sat` ([#5047])
 - Config option `--lease-fee-base-msat` deprecated and will be removed next release ([#5047])
 - Fixed `experimental-websocket-port` to work with default addresses. ([#4945])
 - Protocol: removed support for v0.10.1 onion messages. ([#4921])
 - Protocol: Ability to announce DNS addresses ([#4829])
 - Protocol: disabled websocket announcement due to LND propagation issues ([#5200])


[#4829]: https://github.com/ElementsProject/lightning/pull/4829
[#4864]: https://github.com/ElementsProject/lightning/pull/4864
[#4890]: https://github.com/ElementsProject/lightning/pull/4890
[#4896]: https://github.com/ElementsProject/lightning/pull/4896
[#4897]: https://github.com/ElementsProject/lightning/pull/4897
[#4900]: https://github.com/ElementsProject/lightning/pull/4900
[#4902]: https://github.com/ElementsProject/lightning/pull/4902
[#4906]: https://github.com/ElementsProject/lightning/pull/4906
[#4908]: https://github.com/ElementsProject/lightning/pull/4908
[#4911]: https://github.com/ElementsProject/lightning/pull/4911
[#4913]: https://github.com/ElementsProject/lightning/pull/4913
[#4921]: https://github.com/ElementsProject/lightning/pull/4921
[#4925]: https://github.com/ElementsProject/lightning/pull/4925
[#4929]: https://github.com/ElementsProject/lightning/pull/4929
[#4931]: https://github.com/ElementsProject/lightning/pull/4931
[#4945]: https://github.com/ElementsProject/lightning/pull/4945
[#4984]: https://github.com/ElementsProject/lightning/pull/4984
[#4985]: https://github.com/ElementsProject/lightning/pull/4985
[#5004]: https://github.com/ElementsProject/lightning/pull/5004
[#5010]: https://github.com/ElementsProject/lightning/pull/5010
[#5013]: https://github.com/ElementsProject/lightning/pull/5013
[#5016]: https://github.com/ElementsProject/lightning/pull/5016
[#5019]: https://github.com/ElementsProject/lightning/pull/5019
[#5043]: https://github.com/ElementsProject/lightning/pull/5043
[#5047]: https://github.com/ElementsProject/lightning/pull/5047
[#5051]: https://github.com/ElementsProject/lightning/pull/5051
[#5052]: https://github.com/ElementsProject/lightning/pull/5052
[#5058]: https://github.com/ElementsProject/lightning/pull/5058
[#5078]: https://github.com/ElementsProject/lightning/pull/5078
[#5081]: https://github.com/ElementsProject/lightning/pull/5081
[#5085]: https://github.com/ElementsProject/lightning/pull/5085
[#5086]: https://github.com/ElementsProject/lightning/pull/5086
[#5090]: https://github.com/ElementsProject/lightning/pull/5090
[#5101]: https://github.com/ElementsProject/lightning/pull/5101
[#5103]: https://github.com/ElementsProject/lightning/pull/5103
[#5104]: https://github.com/ElementsProject/lightning/pull/5104
[#5120]: https://github.com/ElementsProject/lightning/pull/5120
[#5121]: https://github.com/ElementsProject/lightning/pull/5121
[#5122]: https://github.com/ElementsProject/lightning/pull/5122
[#5130]: https://github.com/ElementsProject/lightning/pull/5130
[#5136]: https://github.com/ElementsProject/lightning/pull/5136
[#5146]: https://github.com/ElementsProject/lightning/pull/5146
[#5200]: https://github.com/ElementsProject/lightning/pull/5200
[0.11.0]: https://github.com/ElementsProject/lightning/releases/tag/v0.11.0

## [0.10.2] - 2021-11-03: Bitcoin Dust Consensus Rule

This release named by @vincenzopalazzo.

### Added

 - config: new option `--max-dust-htlc-exposure-msat`, which limits the total amount of sats to be allowed as dust on a channel ([#4837])
 - With `sqlite3` db backend we now use a 60-second busy timer, to allow backup processes like `litestream` to operate safely. ([#4867])
 - pay: Payment attempts are now grouped by the pay command that initiated them ([#4567])
 - JSON-RPC: `setchannelfee` gives a grace period (`enforcedelay`) before rejecting old-fee payments: default 10 minutes. ([#4806])
 - Support filtering `listpays` by their status. ([#4595])
 - `close` now notifies about the feeranges each side uses. ([#4784])
 - Protocol: We now send and support `channel_type` in channel open (not dual-funding though). ([#4616])
 - Protocol: We now perform quick-close if the peer supports it. ([#4599])
 - JSONRPC: `close` now takes a `feerange` parameter to set min/max fee rates for mutual close. ([#4599])
 - Protocol: Allow sending large HTLCs if peer offers `option_support_large_channel` (> 4294967295msat) ([#4599])
 - pyln-client: routines for direct access to the gossip store as Gossmap ([#4582])
 - Plugins: `shutdown` notification for clean exits. ([#4754])
 - Plugins: Added `channel_id` and `commitnum` to `commitment_revocation` hook ([#4760])
 - JSON-RPC: `datastore`, `deldatastore` and `listdatastore` for plugins to store simple persistent key/value data. ([#4674])


### Changed

 - pay: The route selection will now use the log-propability-based channel selection to increase success rate and reduce time to completion ([#4771])
 - Plugins: `pay` now biases towards larger channels, improving success probability. ([#4771])
 - db: removal of old HTLC information and vacuuming shrinks large lightningd.sqlite3 by a factor of 2-3. ([#4850])
 - JSON-RPC: `ping` now only works if we have a channel with the peer. ([#4804])
 - Protocol: Send regular pings to detect dead connections (particularly for Tor). ([#4804])
 - Build: Python is now required to build, as generated files are no longer checked into the repository. ([#4805])
 - pyln-spec: updated to latest BOLT versions. ([#4763])
 - JSON-RPC: Change order parameters in the `listforwards` command ([#4668])
 - db: We now set a busy timeout to safely allow others to access sqlite3 db (e.g. litestream) ([#4554])
 - connectd: Try non-TOR connections first ([#4731])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - Protocol: No longer restrict HTLCs to less than 4294967295msat ([#4599])
 - Change order of the `status` parameter in the `listforwards` rpc command. ([#4668])
 - RPC framework now requires the `"jsonrpc"` property inside the request. ([#4742])
 - Plugins: Renames plugin init `use_proxy_always` to `always_use_proxy` ([#4731])


### Removed



### Fixed

 - peer: Fixed a crash when a connection is lost outside of a DB transaction ([#4894])
 - We now no longer self-limit the number of file descriptors (which limits the number of channels) in sufficiently modern systems, or where we can access `/proc` or `/dev/fd`.  We still self-limit on old systems where we cannot find the list of open files on `/proc` or `/dev/fd`, so if you need > ~4000 channels, upgrade or mount `/proc`. ([#4872])
 - errors: Errors returning a `channel_update` no longer return an outdated one. ([#4876])
 - pay: `listpays` returns payments orderd by their creation date ([#4567])
 - pay: `listpays` no longer groups attempts from multiple attempts to pay an invoice ([#4567])
 - sqlite3: Relaxed the version match requirements to be at least a minimum version and a major version match ([#4852])
 - pay: `pay` would sometimes misreport a final state of `pending` instead of `failed` ([#4803])
 - Plugins: C plugins would could leak memory on every command (esp. seen when hammering topology's `listchannels`). ([#4737])
 - libplugin: Fatal error messages from `plugin_exit()` now logged in lightningd. ([#4754])
 - `openchannel_signed` would fail on PSBT comparison of materially identical PSBTs ([#4752])
 - doc: `listnodes` fields now correctly documented. ([#4750])
 - EXPERIMENTAL: crash for some users while requesting dual funding leases. ([#4751])
 - Plugins: Don't drop complaints about silly channels to `stderr`. ([#4730])
 - connectd: Do not try address hint twice ([#4731])


### EXPERIMENTAL

 - channel_upgrade draft upgraded: cannot upgrade channels until peers also upgrade. ([#4830])
 - bolt12: `chains` in `invoice_request` and invoice is deprecated, `chain` is used instead. ([#4849])
 - bolt12: `vendor` is deprecated: the field is now called `issuer`. ([#4849])
 - Protocol: Updated `onion_message` support to match updated draft specification (with backwards compat for old version) ([#4800])
 - Anchor output mutual close allow a fee higher than the final commitment transaction (as per lightning-rfc #847) ([#4599])

[#4850]: https://github.com/ElementsProject/lightning/pull/4850
[#4599]: https://github.com/ElementsProject/lightning/pull/4599
[#4754]: https://github.com/ElementsProject/lightning/pull/4754
[#4849]: https://github.com/ElementsProject/lightning/pull/4849
[#4730]: https://github.com/ElementsProject/lightning/pull/4730
[#4876]: https://github.com/ElementsProject/lightning/pull/4876
[#4830]: https://github.com/ElementsProject/lightning/pull/4830
[#4668]: https://github.com/ElementsProject/lightning/pull/4668
[#4872]: https://github.com/ElementsProject/lightning/pull/4872
[#4616]: https://github.com/ElementsProject/lightning/pull/4616
[#4752]: https://github.com/ElementsProject/lightning/pull/4752
[#4731]: https://github.com/ElementsProject/lightning/pull/4731
[#4554]: https://github.com/ElementsProject/lightning/pull/4554
[#4742]: https://github.com/ElementsProject/lightning/pull/4742
[#4803]: https://github.com/ElementsProject/lightning/pull/4803
[#4737]: https://github.com/ElementsProject/lightning/pull/4737
[#4784]: https://github.com/ElementsProject/lightning/pull/4784
[#4852]: https://github.com/ElementsProject/lightning/pull/4852
[#4849]: https://github.com/ElementsProject/lightning/pull/4849
[#4894]: https://github.com/ElementsProject/lightning/pull/4894
[#4837]: https://github.com/ElementsProject/lightning/pull/4837
[#4771]: https://github.com/ElementsProject/lightning/pull/4771
[#4599]: https://github.com/ElementsProject/lightning/pull/4599
[#4599]: https://github.com/ElementsProject/lightning/pull/4599
[#4567]: https://github.com/ElementsProject/lightning/pull/4567
[#4567]: https://github.com/ElementsProject/lightning/pull/4567
[#4804]: https://github.com/ElementsProject/lightning/pull/4804
[#4742]: https://github.com/ElementsProject/lightning/pull/4742
[#4805]: https://github.com/ElementsProject/lightning/pull/4805
[#4750]: https://github.com/ElementsProject/lightning/pull/4750
[#4595]: https://github.com/ElementsProject/lightning/pull/4595
[#4567]: https://github.com/ElementsProject/lightning/pull/4567
[#4763]: https://github.com/ElementsProject/lightning/pull/4763
[#4668]: https://github.com/ElementsProject/lightning/pull/4668
[#4806]: https://github.com/ElementsProject/lightning/pull/4806
[#4731]: https://github.com/ElementsProject/lightning/pull/4731
[#4582]: https://github.com/ElementsProject/lightning/pull/4582
[#4771]: https://github.com/ElementsProject/lightning/pull/4771
[#4751]: https://github.com/ElementsProject/lightning/pull/4751
[#4599]: https://github.com/ElementsProject/lightning/pull/4599
[#4804]: https://github.com/ElementsProject/lightning/pull/4804
[#4800]: https://github.com/ElementsProject/lightning/pull/4800
[#4754]: https://github.com/ElementsProject/lightning/pull/4754
[#4599]: https://github.com/ElementsProject/lightning/pull/4599
[#4674]: https://github.com/ElementsProject/lightning/pull/4674
[#4731]: https://github.com/ElementsProject/lightning/pull/4731
[#4760]: https://github.com/ElementsProject/lightning/pull/4760
[#4867]: https://github.com/ElementsProject/lightning/pull/4867
[0.10.2]: https://github.com/ElementsProject/lightning/releases/tag/v0.10.2

## [0.10.1] - 2021-08-09: "eltoo: Ethereum Layer Too"

This release named by @nalinbhardwaj.

NOTE ONE: Both the dual-funding and offers protocols have changed, and
are incompatible with older releases (they're both still draft) #reckless

NOTE TWO: `rebalance` and `drain` plugins will need to be redownloaded as
older versions will no longer work -- `payment_secret` is now compulsory.


### Added

 - JSON-RPC: `invoice` now outputs explicit `payment_secret` as its own field. ([#4646])
 - JSON-RPC: `listchannels` can be queried by `destination`. ([#4614])
 - JSON-RPC: `invoice` now gives `warning_private_unused` if unused unannounced channels could have provided sufficient capacity. ([#4585])
 - JSON-RPC: `withdraw`, `close` (and others) now accept taproot (and other future) segwit addresses. ([#4591])
 - JSON-RPC: HTLCs in `listpeers` are now annotated with a status if they are waiting on an `htlc_accepted` hook of a plugin. ([#4580])
 - JSON-RPC: `close` returns `type` "unopened" if it simply discards channel instead of empty object. ([#4501])
 - JSON-RPC: `listfunds` has a new `reserved_to_block` field. ([#4510])
 - JSON-RPC: `createonion` RPC command now accepts an optional `onion_size`. ([#4519])
 - JSON-RPC: new command `parsefeerate` which takes a feerate string and returns the calculated perkw/perkb ([#4639])
 - Protocol: `option_shutdown_anysegwit` allows future segwit versions on shutdown transactions. ([#4556])
 - Protocol: We now send and accept `option_shutdown_anysegwit` so you can close channels to v1+ segwit addresses. ([#4591])
 - Plugins: Plugins may now send custom notifications that other plugins can subscribe to. ([#4496])
 - Plugins: Add `funder` plugin, which allows you to setup a policy for funding v2 channel open requests. Requres --experimental-dual-fund option ([#4489])
 - Plugins: `funder` plugin includes command `funderupdate` which will show current funding configuration and allow you to modify them ([#4489])
 - Plugins: Restart plugin on `rescan` when binary was changed. ([#4609])
 - keysend: `keysend` can now reach non-public nodes by providing the `routehints` argument if they are known. ([#4611])
 - keysend: You can now add extra TLVs to a payment sent via `keysend` ([#4610])
 - config: `force_feerates` option to allow overriding feerate estimates (mainly for regtest). ([#4629])
 - config: New option `log-timestamps` allow disabling of timestamp prefix in logs. ([#4504])
 - hsmtool: allow piped passwords ([#4571])
 - libhsmd: Added python bindings for `libhsmd` ([#4498])
 - libhsmd: Extracted the `hsmd` logic into its own library for other projects to use ([#4497])
 - lightningd: we now try to restart if subdaemons are upgraded underneath us. ([#4471])


### Changed

 - JSON-RPC: `invoice` now allows creation of giant invoices (>= 2^32 msat) ([#4606])
 - JSON-RPC: `invoice` warnings are now better defined, and `warning_mpp_capacity` is no longer included (since `warning_capacity` covers that). ([#4585])
 - JSON-RPC: `getroute` is now implemented in a plugin. ([#4585])
 - JSON-RPC: `sendonion` no longer requires the gratuitous `direction` and `channel` fields in the `firsthop` parameter. ([#4537])
 - JSON-RPC: moved dev-sendcustommsg to sendcustommsg ([#4650])
 - JSON-RPC: `listpays` output is now ordered by the `created_at` timestamp. ([#4518])
 - JSON-RPC: `listsendpays` output is now ordered by `id`. ([#4518])
 - JSON-RPC: `autocleaninvoice` now returns an object, not a raw string. ([#4501])
 - JSON-RPC: `fundpsbt` will not include UTXOs that aren't economic (can't pay for their own fees), unless 'all' ([#4509])
 - JSON-RPC: `close` now always returns notifications on delays. ([#4465])
 - Protocol: All new invoices require a `payment_secret` (i.e. modern TLV format onion) ([#4646])
 - Protocol: Allow out-of-bound fee updates from peers, as long as they're not getting *worse* ([#4681])
 - Protocol: We can no longer connect to peers which don't support `payment_secret`. ([#4646])
 - Protocol: We will now reestablish and negotiate mutual close on channels we've already closed (great if peer has lost their database). ([#4559])
 - Protocol: We now assume nodes support TLV onions (non-legacy) unless we have a `node_announcement` which says they don't. ([#4646])
 - Protocol: Use a more accurate fee for mutual close negotiation. ([#4619])
 - Protocol: channel feerates reduced to bitcoind's "6 block ECONOMICAL" rate. ([#4507])
 - keysend now uses 22 for the final CLTV, making it rust-lightning compatible. ([#4548])
 - Plugins: `fundchannel` and `multifundchannel` will now reserve funding they use for 2 weeks instead of 12 hours. ([#4510])
 - Plugins: we now always send `allow-deprecated-apis` in getmanifest. ([#4465])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.
 - lightningd: `enable-autotor-v2-mode` option.  Use v3.  See https://blog.torproject.org/v2-deprecation-timeline. ([#4549])
 - lightningd: v2 Tor addresses.  Use v3.  See https://blog.torproject.org/v2-deprecation-timeline. ([#4549])
 - JSON-RPC: `listtransactions` `outputs` `satoshis` field (use `msat` instead). ([#4594])
 - JSON-RPC: `listfunds` `channels` `funding_allocation_msat` and `funding_msat`: use `funding`. ([#4594])
 - JSON-RPC: `listfunds` `channels` `last_tx_fee`: use `last_tx_fee_msat`. ([#4594])
 - JSON-RPC: `listfunds` `channels` `closer` is now omitted if it does not apply, not JSON `null`. ([#4594])

### Removed

 - JSON-RPC: `newaddr` no longer includes `address` field (deprecated in 0.7.1) ([#4465])
 - pyln: removed deprecated `fundchannel`/`fundchannel_start` `satoshi` arg. ([#4465])
 - pyln: removed deprecated pay/sendpay `description` arg. ([#4465])
 - pyln: removed deprecated close `force` variant. ([#4465])

### Fixed

 - JSON-RPC: `listinvoice` no longer crashes if given an invalid (or bolt12) `invstring` argument. ([#4625])
 - JSON-RPC: `listconfigs` would list some boolean options as strings `"true"` or `"false"` instead of using JSON booleans. ([#4594])
 - Protocol: don't ever send 0 `fee_updates` (regtest bug). ([#4629])
 - Protocol: We could get stuck on signature exchange if we needed to retransmit the final `revoke_and_ack`. ([#4559])
 - Protocol: Validate chain hash for `gossip_timestamp_filter` messages ([#4514])
 - Protocol: We would sometimes gratuitously disconnect 30 seconds after an HTLC failed. ([#4550])
 - Protocol: handle complex feerate transitions correctly. ([#4480])
 - Protocol: Don't create more than one feerate change at a time, as this seems to desync with LND. ([#4480])
 - Build: Fixes `make full-check` errors on macOS ([#4613])
 - Build: Fixes `make` with `--enable-developer` option on macOS. ([#4613])
 - Docs: Epic documentation rewrite: each now lists complete and accurate JSON output, tested against testsuite. ([#4594])
 - Config: `addr` autotor and statictor /torport arguments now advertized correctly. ([#4603])
 - pay: Fixed an issue when filtering routehints when we can't find ourselves in the local network view. ([#4581])
 - pay: The presplitter mod will no longer exhaust the HTLC budget. ([#4563])
 - pay: Fix occasional crash paying an invoice with a routehint to us. ([#4555])
 - Compat: Handle windows-style newlines and other trailing whitespaces correctly in bitcoin-cli interface ([#4502])


### EXPERIMENTAL

 - bolt12 decode `timestamp` field deprecated in favor of new name `created_at`. ([#4669])
 - JSON-RPC: `listpeers` now includes the `scratch_txid` for every inflight (if is a dual-funded channel) ([#4521])
 - JSON-RPC: for v2 channels, we now list the inflights information for a channel ([#4521])
 - JSON-RPC: `fetchinvoice` can take a payer note, and `listinvoice` will show the `payer_notes` received. ([#4625])
 - JSON-RPC: `fetchinvoice` and `sendinvoice` will connect directly if they can't find an onionmessage route. ([#4625])
 - JSON-RPC: `openchannel_init` now takes a `requested_amt`, which is an amount to request from peer ([#4639])
 - JSON-RPC: `fundchannel` now takes optional `request_amt` parameter ([#4639])
 - JSON-RPC: `fundchannel`, `multifundchannel`, and `openchannel_init` now accept a `compact_lease` for any requested funds ([#4639])
 - JSON-RPC: close now has parameter to force close a leased channel (`option_will_fund`) ([#4639])
 - JSON-RPC: `listnodes` now includes the `lease_rates`, if available ([#4639])
 - JSON-RPC: new RPC `setleaserates`, for passing in the rates to advertise for a channel lease (`option_will_fund`) ([#4639])
 - JSON-RPC: `decode` now gives a `valid` boolean (it does partial decodes of some invalid data). ([#4501])
 - JSON-RPC: `listoffers` now shows `local_offer_id` when listing all offers. ([#4625])
 - Protocol: we can now upgrade old channels to `option_static_remotekey`. See https://github.com/lightningnetwork/lightning-rfc/pull/868 ([#4532])
 - Protocol: we support the quiescence protocol from https://github.com/lightningnetwork/lightning-rfc/pull/869 ([#4520])
 - Protocol: Replaces `init_rbf`'s `fee_step` for RBF of v2 opens with `funding_feerate_perkw`, breaking change ([#4648])
 - Protocol: BOLT12 offers can now be unsigned, for really short QR codes. ([#4625])
 - Protocol: offer signature format changed. ([#4630])
 - Plugins: `rbf_channel` hook has `channel_max_msat` parameter ([#4489])
 - Plugins: `openchannel2` hook now includes optional fields for a channel lease request ([#4639])
 - Plugins: add a `channel_max_msat` value to the `openchannel2` hook. Tells you the total max funding this channel is allowed to have. ([#4489])
 - funder: `funderupdate` command to view and update params for contributing our wallet funds to v2 channel openings. Provides params for enabling `option_will_fund`. ([#4664])

[#4681]: https://github.com/ElementsProject/lightning/pull/4681
[#4646]: https://github.com/ElementsProject/lightning/pull/4646
[#4625]: https://github.com/ElementsProject/lightning/pull/4625
[#4639]: https://github.com/ElementsProject/lightning/pull/4639
[#4650]: https://github.com/ElementsProject/lightning/pull/4650
[#4646]: https://github.com/ElementsProject/lightning/pull/4646
[#4497]: https://github.com/ElementsProject/lightning/pull/4497
[#4465]: https://github.com/ElementsProject/lightning/pull/4465
[#4619]: https://github.com/ElementsProject/lightning/pull/4619
[#4498]: https://github.com/ElementsProject/lightning/pull/4498
[#4496]: https://github.com/ElementsProject/lightning/pull/4496
[#4585]: https://github.com/ElementsProject/lightning/pull/4585
[#4639]: https://github.com/ElementsProject/lightning/pull/4639
[#4664]: https://github.com/ElementsProject/lightning/pull/4664
[#4518]: https://github.com/ElementsProject/lightning/pull/4518
[#4613]: https://github.com/ElementsProject/lightning/pull/4613
[#4639]: https://github.com/ElementsProject/lightning/pull/4639
[#4563]: https://github.com/ElementsProject/lightning/pull/4563
[#4594]: https://github.com/ElementsProject/lightning/pull/4594
[#4507]: https://github.com/ElementsProject/lightning/pull/4507
[#4489]: https://github.com/ElementsProject/lightning/pull/4489
[#4537]: https://github.com/ElementsProject/lightning/pull/4537
[#4625]: https://github.com/ElementsProject/lightning/pull/4625
[#4625]: https://github.com/ElementsProject/lightning/pull/4625
[#4594]: https://github.com/ElementsProject/lightning/pull/4594
[#4489]: https://github.com/ElementsProject/lightning/pull/4489
[#4501]: https://github.com/ElementsProject/lightning/pull/4501
[#4585]: https://github.com/ElementsProject/lightning/pull/4585
[#4594]: https://github.com/ElementsProject/lightning/pull/4594
[#4559]: https://github.com/ElementsProject/lightning/pull/4559
[#4471]: https://github.com/ElementsProject/lightning/pull/4471
[#4510]: https://github.com/ElementsProject/lightning/pull/4510
[#4648]: https://github.com/ElementsProject/lightning/pull/4648
[#4465]: https://github.com/ElementsProject/lightning/pull/4465
[#4639]: https://github.com/ElementsProject/lightning/pull/4639
[#4521]: https://github.com/ElementsProject/lightning/pull/4521
[#4610]: https://github.com/ElementsProject/lightning/pull/4610
[#4646]: https://github.com/ElementsProject/lightning/pull/4646
[#4510]: https://github.com/ElementsProject/lightning/pull/4510
[#4501]: https://github.com/ElementsProject/lightning/pull/4501
[#4594]: https://github.com/ElementsProject/lightning/pull/4594
[#4639]: https://github.com/ElementsProject/lightning/pull/4639
[#4629]: https://github.com/ElementsProject/lightning/pull/4629
[#4555]: https://github.com/ElementsProject/lightning/pull/4555
[#4606]: https://github.com/ElementsProject/lightning/pull/4606
[#4594]: https://github.com/ElementsProject/lightning/pull/4594
[#4646]: https://github.com/ElementsProject/lightning/pull/4646
[#4548]: https://github.com/ElementsProject/lightning/pull/4548
[#4639]: https://github.com/ElementsProject/lightning/pull/4639
[#4669]: https://github.com/ElementsProject/lightning/pull/4669
[#4571]: https://github.com/ElementsProject/lightning/pull/4571
[#4504]: https://github.com/ElementsProject/lightning/pull/4504
[#4465]: https://github.com/ElementsProject/lightning/pull/4465
[#4489]: https://github.com/ElementsProject/lightning/pull/4489
[#4613]: https://github.com/ElementsProject/lightning/pull/4613
[#4625]: https://github.com/ElementsProject/lightning/pull/4625
[#4614]: https://github.com/ElementsProject/lightning/pull/4614
[#4489]: https://github.com/ElementsProject/lightning/pull/4489
[#4629]: https://github.com/ElementsProject/lightning/pull/4629
[#4603]: https://github.com/ElementsProject/lightning/pull/4603
[#4625]: https://github.com/ElementsProject/lightning/pull/4625
[#4594]: https://github.com/ElementsProject/lightning/pull/4594
[#4520]: https://github.com/ElementsProject/lightning/pull/4520
[#4509]: https://github.com/ElementsProject/lightning/pull/4509
[#4521]: https://github.com/ElementsProject/lightning/pull/4521
[#4549]: https://github.com/ElementsProject/lightning/pull/4549
[#4639]: https://github.com/ElementsProject/lightning/pull/4639
[#4518]: https://github.com/ElementsProject/lightning/pull/4518
[#4585]: https://github.com/ElementsProject/lightning/pull/4585
[#4630]: https://github.com/ElementsProject/lightning/pull/4630
[#4480]: https://github.com/ElementsProject/lightning/pull/4480
[#4501]: https://github.com/ElementsProject/lightning/pull/4501
[#4549]: https://github.com/ElementsProject/lightning/pull/4549
[#4550]: https://github.com/ElementsProject/lightning/pull/4550
[#4591]: https://github.com/ElementsProject/lightning/pull/4591
[#4609]: https://github.com/ElementsProject/lightning/pull/4609
[#4465]: https://github.com/ElementsProject/lightning/pull/4465
[#4532]: https://github.com/ElementsProject/lightning/pull/4532
[#4513]: https://github.com/ElementsProject/lightning/pull/4513
[#4514]: https://github.com/ElementsProject/lightning/pull/4514
[#4591]: https://github.com/ElementsProject/lightning/pull/4591
[#4465]: https://github.com/ElementsProject/lightning/pull/4465
[#4611]: https://github.com/ElementsProject/lightning/pull/4611
[#4559]: https://github.com/ElementsProject/lightning/pull/4559
[#4465]: https://github.com/ElementsProject/lightning/pull/4465
[#4639]: https://github.com/ElementsProject/lightning/pull/4639
[#4581]: https://github.com/ElementsProject/lightning/pull/4581
[#4519]: https://github.com/ElementsProject/lightning/pull/4519
[#4639]: https://github.com/ElementsProject/lightning/pull/4639
[#4502]: https://github.com/ElementsProject/lightning/pull/4502
[#4556]: https://github.com/ElementsProject/lightning/pull/4556
[#4580]: https://github.com/ElementsProject/lightning/pull/4580
[#4480]: https://github.com/ElementsProject/lightning/pull/4480
[0.10.1rc2]: https://github.com/ElementsProject/lightning/releases/tag/v0.10.1rc2


## [0.10.0] - 2021-03-28: Neutralizing Fee Therapy

This release named by @jsarenik.

### Added

 - Protocol: we treat error messages from peer which refer to "all channels" as warnings, not errors. ([#4364])
 - Protocol: we now report the new (draft) warning message. ([#4364])
 - JSON-RPC: `connect` returns `address` it actually connected to ([#4436])
 - JSON-RPC: `connect` returns "direction" ("in": they initiated, or "out": we initiated) ([#4452])
 - JSON-RPC: `txprepare` and `withdraw` now return a `psbt` field. ([#4428])
 - JSON-RPC: `fundchannel_complete` takes a psbt parameter. ([#4428])
 - pay: `pay` will now remove routehints that are unusable due to the entrypoint being unknown or unreachable. ([#4404])
 - Plugins: `peer_connected` hook and `connect` notifications have "direction" field. ([#4452])
 - Plugins: If there is a misconfiguration with important plugins we now abort early with a more descriptive error message. ([#4418])
 - pyln: Plugins that are run from the command line print helpful information on how to configure c-lightning to include them and print metadata about what RPC methods and options are exposed. ([#4419])
 - JSON-RPC: `listpeers` now shows latest feerate and unilateral close fee. ([#4407])
 - JSON-RPC: `listforwards` can now filter by status, in and out channel. ([#4349])
 - JSON-RPC: Add new parameter `excess_as_change` to fundpsbt+utxopsbt ([#4368])
 - JSON-RPC: `addgossip` allows direct injection of network gossip messages. ([#4361])
 - pyln-testing: The RPC client will now pretty-print requests and responses to facilitate log-based debugging. ([#4357])


### Changed

 - Plugins: the `rpc_command` hook is now chainable. ([#4384])
 - JSON-RPC: If bitcoind won't give a fee estimate in regtest, use minimum. ([#4405])
 - Protocol: we use `sync_complete` for gossip range query replies, with detection for older spec nodes. ([#4389])
 - Plugins: `peer_connected` rejections now send a warning, not an error, to the peer. ([#4364])
 - Protocol: we now send warning messages and close the connection, except on unrecoverable errors. ([#4364])
 - JSON-RPC: `sendpay` no longer extracts updates from errors, the caller should do it from the `raw_message`. ([#4361])
 - Plugins: `peer_connected` hook is now chainable ([#4351])
 - Plugins: `custommsg` hook is now chainable ([#4358])


### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON-RPC: `fundchannel_complete` `txid` and `txout` parameters (use `psbt`) ([#4428])
 - Plugins: The `message` field on the `custommsg` hook is deprecated in favor of the `payload` field, which skips the internal prefix. ([#4394])


### Removed

 - `bcli` replacements must allow `allowhighfees` argument (deprecated 0.9.1). ([#4362])
 - `listsendpays` will no longer add `amount_msat` `null` (deprecated 0.9.1). ([#4362])


### Fixed

 - Protocol: overzealous close when peer sent more HTLCs than they'd told us we could send. ([#4432])
 - pay: Report the correct decoding error if bolt11 parsing fails. ([#4404])
 - pay: `pay` will now abort early if the destination is not reachable directly nor via routehints. ([#4404])
 - pay: `pay` was reporting in-flight parts as failed ([#4404])
 - pay: `pay` would crash on corrupt gossip store, which (if version was ever wrong) we'd corrupt again ([#4453])
 - pyln: Fixed an error when calling `listfunds` with an older c-lightning version causing an error about an unknown `spent` parameter ([#4417])
 - Plugins: `dev-sendcustommsg` included the type and length prefix when sending a message. ([#4413])
 - Plugins: The `custommsg` hook no longer includes the internal type prefix and length prefix in its `payload` ([#4394])
 - db: Fixed an access to a NULL-field in the `channel_htlcs` table and resulting warning. ([#4378])
 - pay: Payments with an empty route (self-payment) are now aborted. ([#4379])
 - Protocol: always accept channel_updates from errors, even they'd otherwise be rejected as spam. ([#4361])
 - connectd: Occasional crash in connectd due to use-after-free ([#4360])
 - lightningd: JSON failures when --daemon is used without --log-file. ([#4350])
 - lightningd: don't assert if time goes backwards temporarily. ([#4449])


### EXPERIMENTAL

These options are either enabled by explicit *experimental* config
parameters, or building with `--enable-experimental-features`.

 - lightningd: `experimental-dual-fund` runtime flag will enable dual-funded protocol on this node ([#4427])
 - lightningd: `experimental-shutdown-wrong-funding` to allow remote nodes to close incorrectly opened channels. ([#4421])
 - JSON-RPC: close has a new `wrong_funding` option to try to close out unused channels where we messed up the funding tx. ([#4421])
 - JSON-RPC: Permit user-initiated aborting of in-progress opens. Only valid for not-yet-committed opens and RBF-attempts ([#4424])
 - JSON-RPC: `listpeers` now includes 'last_feerate', 'next_feerate', 'initial_feerate' and 'next_fee_step' for channels in state DUALOPEND_AWAITING_LOCKIN ([#4399])


[#4424]: https://github.com/ElementsProject/lightning/pull/4424
[#4358]: https://github.com/ElementsProject/lightning/pull/4358
[#4428]: https://github.com/ElementsProject/lightning/pull/4428
[#4361]: https://github.com/ElementsProject/lightning/pull/4361
[#4379]: https://github.com/ElementsProject/lightning/pull/4379
[#4428]: https://github.com/ElementsProject/lightning/pull/4428
[#4404]: https://github.com/ElementsProject/lightning/pull/4404
[#4361]: https://github.com/ElementsProject/lightning/pull/4361
[#4364]: https://github.com/ElementsProject/lightning/pull/4364
[#4405]: https://github.com/ElementsProject/lightning/pull/4405
[#4436]: https://github.com/ElementsProject/lightning/pull/4436
[#4418]: https://github.com/ElementsProject/lightning/pull/4418
[#4421]: https://github.com/ElementsProject/lightning/pull/4421
[#4413]: https://github.com/ElementsProject/lightning/pull/4413
[#4407]: https://github.com/ElementsProject/lightning/pull/4407
[#4389]: https://github.com/ElementsProject/lightning/pull/4389
[#4360]: https://github.com/ElementsProject/lightning/pull/4360
[#4394]: https://github.com/ElementsProject/lightning/pull/4394
[#4364]: https://github.com/ElementsProject/lightning/pull/4364
[#4399]: https://github.com/ElementsProject/lightning/pull/4399
[#4350]: https://github.com/ElementsProject/lightning/pull/4350
[#4404]: https://github.com/ElementsProject/lightning/pull/4404
[#4404]: https://github.com/ElementsProject/lightning/pull/4404
[#4432]: https://github.com/ElementsProject/lightning/pull/4432
[#4349]: https://github.com/ElementsProject/lightning/pull/4349
[#4362]: https://github.com/ElementsProject/lightning/pull/4362
[#4419]: https://github.com/ElementsProject/lightning/pull/4419
[#4421]: https://github.com/ElementsProject/lightning/pull/4421
[#4394]: https://github.com/ElementsProject/lightning/pull/4394
[#4364]: https://github.com/ElementsProject/lightning/pull/4364
[#4361]: https://github.com/ElementsProject/lightning/pull/4361
[#4384]: https://github.com/ElementsProject/lightning/pull/4384
[#4364]: https://github.com/ElementsProject/lightning/pull/4364
[#4357]: https://github.com/ElementsProject/lightning/pull/4357
[#4368]: https://github.com/ElementsProject/lightning/pull/4368
[#4362]: https://github.com/ElementsProject/lightning/pull/4362
[#4404]: https://github.com/ElementsProject/lightning/pull/4404
[#4378]: https://github.com/ElementsProject/lightning/pull/4378
[#4428]: https://github.com/ElementsProject/lightning/pull/4428
[#4417]: https://github.com/ElementsProject/lightning/pull/4417
[#4351]: https://github.com/ElementsProject/lightning/pull/4351

## [0.9.3] - 2021-01-20: Federal Qualitative Strengthening

This release named by Karol Hosiawa.

### Added

 - JSON-RPC: The `listfunds` method now includes spent outputs if the `spent` parameter is set to true. ([#4296])
 - JSON-RPC: `createinvoice` new low-level invoice creation API. ([#4256])
 - JSON-RPC: `invoice` now takes an optional `cltv` parameter. ([#4320])
 - JSON-RPC: `listinvoices` can now query for an invoice matching a `payment_hash` or a `bolt11` string, in addition to `label` ([#4312])
 - JSON-RPC: fundpsbt/utxopsbt have new param, `min_witness_utxo`, which sets a floor for the weight calculation of an added input ([#4211])
 - docs: `doc/BACKUP.md` describes how to back up your C-lightning node. ([#4207])
 - fee_base and fee_ppm to listpeers ([#4247])
 - hsmtool: password must now be entered on stdin. Password passed on the command line are discarded. ([#4303])
 - plugins: `start` command can now take plugin-specific parameters. ([#4278])
 - plugins: new "multi" field allows an option to be specified multiple times. ([#4278])
 - pyln-client: `fundpsbt`/`utxopsbt` now support `min_witness_weight` param ([#4295])
 - pyln: Added support for command notifications to LightningRpc via the `notify` context-manager. ([#4311])
 - pyln: Plugin methods can now report progress or status via the `Request.notify` function ([#4311])
 - pyln: plugins can now raise RpcException for finer control over error returns. ([#4279])
 - experimental-offers: enables fetch, payment and creation of (early draft) offers. ([#4328])
 - libplugin: init can return a non-NULL string to disable the plugin. ([#4328])
 - plugins: plugins can now disable themselves by returning `disable`, even if marked important. ([#4328])
 - experimental-onion-messages enables send, receive and relay of onion messages. ([#4328])

### Changed

 - JSON-RPC: invalid UTF-8 strings now rejected. ([#4227])
 - bitcoin: The default network was changed from "testnet" to "mainnet", this only affects new nodes ([#4277])
 - cli: `lightning-cli` now performs better sanity checks on the JSON-RPC requests it sends. ([#4259])
 - hsmd: we now error at startup on invalid hsm_secret ([#4307])
 - hsmtool: all commands now error on invalid hsm_secret ([#4307])
 - hsmtool: the `encrypt` now asks you to confirm your password ([#4307])
 - lightningd: the `--encrypted-hsm` now asks you to confirm your password when first set ([#4307])
 - plugins: Multiple plugins can now register `db_write` hooks. ([#4220])
 - plugins: more than one plugin can now register `invoice_payment` hook. ([#4226])
 - pyln: Millisatoshi has new method, `to_whole_satoshi`; *rounds value up* to the nearest whole satoshi ([#4295])
 - pyln: `txprepare` no longer supports the deprecated `destination satoshi feerate utxos` call format. ([#4259])

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

### Removed

 - plugins: options to `init` are no longer given as strings if they are bool or int types (deprecated in 0.8.2). ([#4278])

### Fixed

 - JSON-RPC: The status of the shutdown meesages being exchanged is now displayed correctly. ([#4263])
 - JSONRPC: `setchannelfee` would fail an assertion if channel wasn't in normal state. ([#4282])
 - db: Fixed a performance regression during block sync, resulting in many more queries against the DB than necessary. ([#4319])
 - hsmtool: the `generatehsm` command now generates an appropriately-sized hsm_secret ([#4304])
 - keysend: Keysend now checks whether the destination supports keysend before attempting a payment. If not a more informative error is returned. ([#4236])
 - log: Do not terminate on the second received SIGHUP. ([#4243])
 - onchaind is much faster when unilaterally closing old channels. ([#4250])
 - onchaind uses much less memory on unilateral closes for old channels. ([#4250])
 - pay: Fixed an issue where waiting for the blockchain height to sync could time out. ([#4317])
 - pyln: parsing msat from a float string ([#4237])
 - hsmtool: fix a segfault on `dumponchaindescriptors` without network parameter ([#4341])
 - db: Speed up deletion of peer especially when there is a long history with that peer. ([#4337])

### Security

[#4303]: https://github.com/ElementsProject/lightning/pull/4303
[#4278]: https://github.com/ElementsProject/lightning/pull/4278
[#4312]: https://github.com/ElementsProject/lightning/pull/4312
[#4307]: https://github.com/ElementsProject/lightning/pull/4307
[#4304]: https://github.com/ElementsProject/lightning/pull/4304
[#4295]: https://github.com/ElementsProject/lightning/pull/4295
[#4259]: https://github.com/ElementsProject/lightning/pull/4259
[#4211]: https://github.com/ElementsProject/lightning/pull/4211
[#4207]: https://github.com/ElementsProject/lightning/pull/4207
[#4307]: https://github.com/ElementsProject/lightning/pull/4307
[#4236]: https://github.com/ElementsProject/lightning/pull/4236
[#4247]: https://github.com/ElementsProject/lightning/pull/4247
[#4250]: https://github.com/ElementsProject/lightning/pull/4250
[#4220]: https://github.com/ElementsProject/lightning/pull/4220
[#4319]: https://github.com/ElementsProject/lightning/pull/4319
[#4227]: https://github.com/ElementsProject/lightning/pull/4227
[#4256]: https://github.com/ElementsProject/lightning/pull/4256
[#4279]: https://github.com/ElementsProject/lightning/pull/4279
[#4278]: https://github.com/ElementsProject/lightning/pull/4278
[#4307]: https://github.com/ElementsProject/lightning/pull/4307
[#4250]: https://github.com/ElementsProject/lightning/pull/4250
[#4311]: https://github.com/ElementsProject/lightning/pull/4311
[#4320]: https://github.com/ElementsProject/lightning/pull/4320
[#4311]: https://github.com/ElementsProject/lightning/pull/4311
[#4226]: https://github.com/ElementsProject/lightning/pull/4226
[#4259]: https://github.com/ElementsProject/lightning/pull/4259
[#4317]: https://github.com/ElementsProject/lightning/pull/4317
[#4263]: https://github.com/ElementsProject/lightning/pull/4263
[#4295]: https://github.com/ElementsProject/lightning/pull/4295
[#4296]: https://github.com/ElementsProject/lightning/pull/4296
[#4307]: https://github.com/ElementsProject/lightning/pull/4307
[#4237]: https://github.com/ElementsProject/lightning/pull/4237
[#4277]: https://github.com/ElementsProject/lightning/pull/4277
[#4278]: https://github.com/ElementsProject/lightning/pull/4278
[#4243]: https://github.com/ElementsProject/lightning/pull/4243
[#4282]: https://github.com/ElementsProject/lightning/pull/4282
[#4328]: https://github.com/ElementsProject/lightning/pull/4328
[#4341]: https://github.com/ElementsProject/lightning/pull/4341
[#4337]: https://github.com/ElementsProject/lightning/pull/4337
[0.9.3]: https://github.com/ElementsProject/lightning/releases/tag/v0.9.3


## [0.9.2] - 2020-11-20: Now with 0-of-N Multisig

This release named by Sergi Delgado Segura.

* Note: PSBTs now require bitcoind v0.20.1 or above *

### Added

 - JSON-RPC: Added 'state_changes' history to listpeers channels ([4126](https://github.com/ElementsProject/lightning/pull/4126))
 - JSON-RPC: Added 'opener' and 'closer' to listpeers channels ([4126](https://github.com/ElementsProject/lightning/pull/4126))
 - JSON-RPC: `close` now sends notifications for slow closes (if `allow-deprecated-apis`=false) ([4046](https://github.com/ElementsProject/lightning/pull/4046))
 - JSON-RPC: `notifications` command to enable notifications. ([4046](https://github.com/ElementsProject/lightning/pull/4046))
 - JSON-RPC: `multifundchannel` has a new optional argument, 'commitment_feerate', which can be used to differentiate between the funding feerate and the channel's initial commitment feerate ([4139](https://github.com/ElementsProject/lightning/pull/4139))
 - JSON-RPC `fundchannel` now accepts an optional 'close_to' param, a bitcoin address that the channel funding should be sent to on close. Requires `opt_upfront_shutdownscript` ([4132](https://github.com/ElementsProject/lightning/pull/4132))
 - Plugins: Channel closure resaon/cause to channel_state_changed notification ([4126](https://github.com/ElementsProject/lightning/pull/4126))
 - Plugins: `htlc_accepted` hook can now return custom `failure_onion`. ([4187](https://github.com/ElementsProject/lightning/pull/4187))
 - Plugins: hooks can now specify that they must be called 'before' or 'after' other plugins. ([4168](https://github.com/ElementsProject/lightning/pull/4168))
 - hsmtool: a new command was added to hsmtool for dumping descriptors of the onchain wallet ([4171](https://github.com/ElementsProject/lightning/pull/4171))
 - hsmtool: `hsm_secret` generation from a seed-phrase following BIP39. ([4065](https://github.com/ElementsProject/lightning/pull/4065))
 - cli: print notifications and progress bars if commands provide them. ([4046](https://github.com/ElementsProject/lightning/pull/4046))
 - pyln-client: pyln.client handles and can send progress notifications. ([4046](https://github.com/ElementsProject/lightning/pull/4046))
 - pyln-client: Plugin method and hook requests prevent the plugin developer from accidentally setting the result multiple times, and will raise an exception detailing where the result was first set. ([4094](https://github.com/ElementsProject/lightning/pull/4094))
 - pyln-client: Plugins have been integrated with the `logging` module for easier debugging and error reporting. ([4101](https://github.com/ElementsProject/lightning/pull/4101))
 - pyln-proto: Added pure python implementation of the sphinx onion creation and processing functionality. ([4056](https://github.com/ElementsProject/lightning/pull/4056))
 - libplugin: routines to send notification updates and progress. ([4046](https://github.com/ElementsProject/lightning/pull/4046))
 - build: clang build now supports --enable-address-sanitizer . ([4013](https://github.com/ElementsProject/lightning/pull/4013))
 - db: Added support for key-value DSNs for postgresql, allowing for a wider variety of configurations and environments. ([4072](https://github.com/ElementsProject/lightning/pull/4072))

### Changed

 - * Requires bitcoind v0.20.1 or above * ([4179](https://github.com/ElementsProject/lightning/pull/4179))
 - Plugins: `pay` will now try disabled channels as a last resort. ([4093](https://github.com/ElementsProject/lightning/pull/4093))
 - Protocol: mutual closing feerate reduced to "slow" to avoid overpaying. ([4113](https://github.com/ElementsProject/lightning/pull/4113))
 - In-memory log buffer reduced from 100MB to 10MB ([4087](https://github.com/ElementsProject/lightning/pull/4087))

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - cli: scripts should filter out '^# ' or use `-N none`, as commands will start returning notifications soon ([4046](https://github.com/ElementsProject/lightning/pull/4046))

### Removed

 - Protocol: Support for receiving full gossip from ancient LND nodes. ([4184](https://github.com/ElementsProject/lightning/pull/4184))
 - JSON-RPC: `plugin stop` result with an empty ("") key (deprecated 0.8.1) ([4049](https://github.com/ElementsProject/lightning/pull/4049))
 - JSON-RPC: The hook `rpc_command` returning `{"continue": true}` (deprecated 0.8.1) ([4049](https://github.com/ElementsProject/lightning/pull/4049))
 - JSON-RPC: The hook `db_write` can no longer return `true` (deprecated in 0.8.1) ([4049](https://github.com/ElementsProject/lightning/pull/4049))
 - JSON-RPC: `htlc_accepted` hook `per_hop_v0` object removed (deprecated 0.8.0) ([4049](https://github.com/ElementsProject/lightning/pull/4049))
 - JSON-RPC: `listconfigs` duplicated "plugin" paths (deprecated 0.8.0) ([4049](https://github.com/ElementsProject/lightning/pull/4049))
 - Plugin: Relative plugin paths are not relative to startup (deprecated v0.7.2.1) ([4049](https://github.com/ElementsProject/lightning/pull/4049))

### Fixed

 - Network: Fixed a race condition when us and a peer attempt to make channels to each other at nearly the same time. ([4116](https://github.com/ElementsProject/lightning/pull/4116))
 - Protocol: fixed retransmission order of multiple new HTLCs (causing channel close with LND) ([4124](https://github.com/ElementsProject/lightning/pull/4124))
 - Protocol: `signet` is now compatible with the final bitcoin-core version ([4078](https://github.com/ElementsProject/lightning/pull/4078))
 - Crash: assertion fail at restart when source and destination channels of an HTLC are both onchain. ([4122](https://github.com/ElementsProject/lightning/pull/4122))
 - We are now able to parse any amount string (XXXmsat, XX.XXXbtc, ..) we create. ([4129](https://github.com/ElementsProject/lightning/pull/4129))
 - Some memory leaks in transaction and PSBT manipulate closed. ([4071](https://github.com/ElementsProject/lightning/pull/4071))
 - openingd now uses the correct dust limit for determining the allowable floor for a channel open (affects fundee only) ([4141](https://github.com/ElementsProject/lightning/pull/4141))
 - Plugin: Regression with SQL statement expansion that could result in invalid statements being passed to the `db_write` hook. ([4090](https://github.com/ElementsProject/lightning/pull/4090))
 - build: no longer spuriously regenerates generated sources due to differences in `readdir`(3) sort order. ([4053](https://github.com/ElementsProject/lightning/pull/4053))
 - db: Fixed a broken migration on postgres DBs that had really old channels. ([4064](https://github.com/ElementsProject/lightning/pull/4064))

### Security




## [0.9.1] - 2020-09-15: The Antiguan BTC Maximalist Society

This release named by Jon Griffiths.

### Added

 - JSON-RPC: `multiwithdraw` command to batch multiple onchain sends in a single transaction.  Note it shuffles inputs and outputs, does not use BIP69. ([3812](https://github.com/ElementsProject/lightning/pull/3812))
 - JSON-RPC: `multifundchannel` command to fund multiple channels to different peers all in a single onchain transaction. ([3763](https://github.com/ElementsProject/lightning/pull/3763))
 - JSON-RPC: `delpay` command to delete a payment once completed or failed. ([3899](https://github.com/ElementsProject/lightning/pull/3899))
 - Plugins: `channel_state_changed` notification ([4020](https://github.com/ElementsProject/lightning/pull/4020))
 - JSON-RPC: `listpays` can be used to query payments using the `payment_hash` ([3888](https://github.com/ElementsProject/lightning/pull/3888))
 - JSON-RPC: `listpays` now includes the `payment_hash` ([3888](https://github.com/ElementsProject/lightning/pull/3888))
 - JSON-RPC: `listpays` now includes the timestamp of the first part of the payment ([3909](https://github.com/ElementsProject/lightning/pull/3909))
 - Build: New reproducible build system now uses docker: try it at home with `doc/REPRODUCIBLE.md`! ([4021](https://github.com/ElementsProject/lightning/pull/4021))
 - Plugins: Proxy information now provided in `init.configuration`. ([4010](https://github.com/ElementsProject/lightning/pull/4010))
 - Plugins: `openchannel_hook` is now chainable ([3960](https://github.com/ElementsProject/lightning/pull/3960))
 - JSON-RPC: `listpeers` shows `features` list for each channel. ([3963](https://github.com/ElementsProject/lightning/pull/3963))
 - JSON-RPC: `signpsbt` takes an optional `signonly` array to limit what inputs to sign. ([3954](https://github.com/ElementsProject/lightning/pull/3954))
 - JSON-RPC: `utxopsbt` takes a new `locktime` parameter ([3954](https://github.com/ElementsProject/lightning/pull/3954))
 - JSON-RPC: `fundpsbt` takes a new `locktime` parameter ([3954](https://github.com/ElementsProject/lightning/pull/3954))
 - JSON-RPC: New low-level command `utxopsbt` to create PSBT from existing utxos. ([3845](https://github.com/ElementsProject/lightning/pull/3845))
 - JSON-RPC: `listfunds` now has a `redeemscript` field for p2sh-wrapped outputs. ([3844](https://github.com/ElementsProject/lightning/pull/3844))
 - JSON-RPC: `fundchannel` has new `outnum` field indicating which output of the transaction funds the channel. ([3844](https://github.com/ElementsProject/lightning/pull/3844))
 - pyln-client: commands and options can now mark themselves deprecated. ([3883](https://github.com/ElementsProject/lightning/pull/3883))
 - Plugins: can now mark their options and commands deprecated. ([3883](https://github.com/ElementsProject/lightning/pull/3883))
 - plugins: `getmanifest` may now include "allow-deprecated-apis" boolean flag. ([3883](https://github.com/ElementsProject/lightning/pull/3883))
 - JSON-RPC: `listpays` now lists the `destination` if it was provided (e.g., via the `pay` plugin or `keysend` plugin) ([3888](https://github.com/ElementsProject/lightning/pull/3888))
 - config: New option `--important-plugin` loads a plugin is so important that if it dies, `lightningd` will exit rather than continue.  You can still `--disable-plugin` it, however, which trumps `--important-plugin` and it will not be started at all. ([3890](https://github.com/ElementsProject/lightning/pull/3890))
 - Plugins: We now explicitly check at startup that our default Bitcoin backend (bitcoind) does relay transactions. ([3889](https://github.com/ElementsProject/lightning/pull/3889))
 - Plugins: We now explicitly check at startup the version of our default Bitcoin backend (bitcoind). ([3889](https://github.com/ElementsProject/lightning/pull/3889))

### Changed

 - Build: we no longer require extra Python modules to build. ([3994](https://github.com/ElementsProject/lightning/pull/3994))
 - Build: SQLite3 is no longer a hard build requirement. C-Lightning can now be built to support only the PostgreSQL back-end. ([3999](https://github.com/ElementsProject/lightning/pull/3999))
 - gossipd: The `gossipd` is now a lot quieter, and will log only when a message changed our network topology. ([3981](https://github.com/ElementsProject/lightning/pull/3981))
 - Protocol: We now make MPP-aware routehints in invoices. ([3913](https://github.com/ElementsProject/lightning/pull/3913))
 - onchaind: We now scorch the earth on theft attempts, RBFing up our penalty transaction as blocks arrive without a penalty transaction getting confirmed. ([3870](https://github.com/ElementsProject/lightning/pull/3870))
 - Protocol: `fundchannel` now shuffles inputs and outputs, and no longer follows BIP69. ([3769](https://github.com/ElementsProject/lightning/pull/3769))
 - JSON-RPC: `withdraw` now randomizes input and output order, not BIP69. ([3867](https://github.com/ElementsProject/lightning/pull/3867))
 - JSON-RPC: `txprepare` reservations stay across restarts: use `fundpsbt`/`reservepsbt`/`unreservepsbt` ([3867](https://github.com/ElementsProject/lightning/pull/3867))
 - config: `min-capacity-sat` is now stricter about checking usable capacity of channels. ([3969](https://github.com/ElementsProject/lightning/pull/3969))
 - Protocol: Ignore (and log as "unusual") repeated `WIRE_CHANNEL_REESTABLISH` messages, to be compatible with buggy peer software that sometimes does this. ([3964](https://github.com/ElementsProject/lightning/pull/3964))
 - contrib: startup_regtest.sh `startup_ln` now takes a number of nodes to create as a parameter ([3992](https://github.com/ElementsProject/lightning/pull/3992))
 - JSON-RPC: `invoice` no longer accepts zero amounts (did you mean "any"?) ([3974](https://github.com/ElementsProject/lightning/pull/3974))
 - Protocol: channels now pruned after two weeks unless both peers refresh it (see lightning-rfc#767) ([3959](https://github.com/ElementsProject/lightning/pull/3959))
 - Protocol: bolt11 invoices always include CLTV fields (see lightning-rfc#785) ([3959](https://github.com/ElementsProject/lightning/pull/3959))
 - config: the default CLTV expiry is now 34 blocks, and final expiry 18 blocks as per new BOLT recommendations. ([3959](https://github.com/ElementsProject/lightning/pull/3959))
 - Plugins: Builtin plugins are now marked as important, and if they crash, will cause C-lightning to stop as well. ([3890](https://github.com/ElementsProject/lightning/pull/3890))
 - Protocol: Funding timeout is now based on the header count reported by the bitcoin backend instead of our current blockheight which might be lower. ([3897](https://github.com/ElementsProject/lightning/pull/3897))
 - JSON-RPC: `delinvoice` will now report specific error codes: 905 for failing to find the invoice, 906 for the invoice status not matching the parameter. ([3853](https://github.com/ElementsProject/lightning/pull/3853))

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - Plugins: `bcli` replacements should note that `sendrawtransaction` now has a second required Boolean argument, `allowhighfees`, which if `true`, means ignore any fee limits and just broadcast the transaction. ([3870](https://github.com/ElementsProject/lightning/pull/3870))
 - JSON-RPC: `listsendpays` will no longer add `null` if we don't know the `amount_msat` for a payment. ([3883](https://github.com/ElementsProject/lightning/pull/3883))
 - Plugins: `getmanifest` without any parameters; plugins should accept any parameters for future use. ([3883](https://github.com/ElementsProject/lightning/pull/3883))

### Removed

 - JSON-RPC: txprepare `destination` `satoshi` argument form removed (deprecated v0.7.3) ([3867](https://github.com/ElementsProject/lightning/pull/3867))

### Fixed

 - Plugins: `pay` `presplit` modifier now supports large payments without exhausting the available HTLCs. ([3986](https://github.com/ElementsProject/lightning/pull/3986))
 - Plugins: `pay` corrects a case where we put the sub-payment value instead of the *total* value in the `total_msat` field of a multi-part payment. ([3914](https://github.com/ElementsProject/lightning/pull/3914))
 - Plugins: `pay` is less aggressive with forgetting routehints. ([3914](https://github.com/ElementsProject/lightning/pull/3914))
 - Plugins: `pay` no longer ignores routehints if the payment exceeds 10,000 satoshi. This is particularly bad if the payee is only reachable via routehints in an invoice. ([3908](https://github.com/ElementsProject/lightning/pull/3908))
 - Plugins: `pay` limits the number of splits if the payee seems to have a low number of channels that can enter it, given the max-concurrent-htlcs limit. ([3936](https://github.com/ElementsProject/lightning/pull/3936))
 - Plugins: `pay` will now make reliable multi-part payments to nodes it doesn't have a node_announcement for. ([4035](https://github.com/ElementsProject/lightning/pull/4035))
 - JSON-RPC: significant speedups for plugins which create large JSON replies (e.g. listpays on large nodes). ([3957](https://github.com/ElementsProject/lightning/pull/3957))
 - doc: Many missing manual pages were completed ([3938](https://github.com/ElementsProject/lightning/pull/3938))
 - Build: Fixed compile error on macos ([4019](https://github.com/ElementsProject/lightning/pull/4019))
 - pyln: Fixed HTLCs hanging indefinitely if the hook function raises an exception. A safe fallback result is now returned instead. ([4031](https://github.com/ElementsProject/lightning/pull/4031))
 - Protocol: We now hang up if peer doesn't respond to init message after 60 seconds. ([4039](https://github.com/ElementsProject/lightning/pull/4039))
 - elementsd: PSBTs include correct witness_utxo struct for elements transactions ([4033](https://github.com/ElementsProject/lightning/pull/4033))
 - cli: fixed crash with `listconfigs` in `-H` mode ([4012](https://github.com/ElementsProject/lightning/pull/4012))
 - Plugins: `bcli` significant speedups for block synchronization ([3985](https://github.com/ElementsProject/lightning/pull/3985))
 - Build: On systems with multiple installed versions of the PostgreSQL client library, C-Lightning might link against the wrong version or fail to find the library entirely. `./configure` now uses `pg_config` to locate the library. ([3995](https://github.com/ElementsProject/lightning/pull/3995))
 - Build: On some operating systems the postgresql library would not get picked up. `./configure` now uses `pg_config` to locate the headers. ([3991](https://github.com/ElementsProject/lightning/pull/3991))
 - libplugin: significant speedups for reading large JSON replies (e.g. calling listsendpays on large nodes, or listchannels / listnodes). ([3957](https://github.com/ElementsProject/lightning/pull/3957))

### Security


## [0.9.0] - 2020-07-31: "Rat Poison Squared on Steroids"

This release was named by Sebastian Falbesoner.

### Added

 - plugin: `pay` was rewritten to use the new payment flow. See `legacypay` for old version ([3809](https://github.com/ElementsProject/lightning/pull/3809))
 - plugin: `pay` will split payments that are failing due to their size into smaller parts, if recipient supports the `basic_mpp` option ([3809](https://github.com/ElementsProject/lightning/pull/3809))
 - plugin: `pay` will split large payments into parts of approximately 10k sat if the recipient supports the `basic_mpp` option ([3809](https://github.com/ElementsProject/lightning/pull/3809))
 - plugin: The pay plugin has a new `--disable-mpp` flag that allows opting out of the above two multi-part payment addition.  ([3809](https://github.com/ElementsProject/lightning/pull/3809))
 - JSON-RPC: new low-level coin selection `fundpsbt` routine. ([3825](https://github.com/ElementsProject/lightning/pull/3825))
 - JSON-RPC: The `pay` command now uses the new payment flow, the new `legacypay` command can be used to issue payment with the legacy code if required. ([3826](https://github.com/ElementsProject/lightning/pull/3826))
 - JSON-RPC: The `keysend` command allows sending to a node without requiring an invoice first. ([3792](https://github.com/ElementsProject/lightning/pull/3792))
 - JSON-RPC: `listfunds` now has a 'scriptpubkey' field. ([3821](https://github.com/ElementsProject/lightning/pull/3821))
 - docker: Docker build now includes `LIGHTNINGD_NETWORK` ENV variable which defaults to "bitcoin". An user can override this (e.g. by `-e` option in `docker run`) to run docker container in regtest or testnet or any valid argument to `--network`. ([3813](https://github.com/ElementsProject/lightning/pull/3813))
 - cli: We now install `lightning-hsmtool` for your `hsm_secret` needs. ([3802](https://github.com/ElementsProject/lightning/pull/3802))
 - JSON-RPC: new call `signpsbt` which will add the wallet's signatures to a provided psbt ([3775](https://github.com/ElementsProject/lightning/pull/3775))
 - JSON-RPC: new call `sendpsbt` which will finalize and send a signed PSBT ([3775](https://github.com/ElementsProject/lightning/pull/3775))
 - JSON-RPC: Adds two new rpc methods, `reserveinputs` and `unreserveinputs`, which allow for reserving or unreserving wallet UTXOs ([3775](https://github.com/ElementsProject/lightning/pull/3775))
 - Python: `pyln.spec.bolt{1,2,4,7}` packages providing python versions of the spec text and defined messages. ([3777](https://github.com/ElementsProject/lightning/pull/3777))
 - pyln: new module `pyln.proto.message.bolts` ([3733](https://github.com/ElementsProject/lightning/pull/3733))
 - cli: New `--flat` mode for easy grepping of `lightning-cli` output. ([3722](https://github.com/ElementsProject/lightning/pull/3722))
 - plugins: new notification type, `coin_movement`, which tracks all fund movements for a node ([3614](https://github.com/ElementsProject/lightning/pull/3614))
 - plugin: Added a new `commitment_revocation` hook that provides the plugin with penalty transactions for all revoked transactions, e.g., to push them to a watchtower. ([3659](https://github.com/ElementsProject/lightning/pull/3659))
 - JSON-API: `listchannels` now shows channel `features`. ([3685](https://github.com/ElementsProject/lightning/pull/3685))
 - plugin: New `invoice_creation` plugin event ([3658](https://github.com/ElementsProject/lightning/pull/3658))
 - docs: Install documentation now has information about building for Alpine linux ([3660](https://github.com/ElementsProject/lightning/pull/3660))
 - plugin: Plugins can opt out of having an RPC connection automatically initialized on startup. ([3857](https://github.com/ElementsProject/lightning/pull/3857))
 - JSON-RPC: `sendonion` has a new optional `bolt11` argument for when it's used to pay an invoice. ([3878](https://github.com/ElementsProject/lightning/pull/3878))
 - JSON-RPC: `sendonion` has a new optional `msatoshi` that is used to annotate the payment with the amount received by the destination. ([3878](https://github.com/ElementsProject/lightning/pull/3881))

### Changed

 - JSON-RPC: `fundchannel_cancel` no longer requires its undocumented `channel_id` argument after `fundchannel_complete`. ([3787](https://github.com/ElementsProject/lightning/pull/3787))
 - JSON-RPC: `fundchannel_cancel` will now succeed even when executed while a `fundchannel_complete` is ongoing; in that case, it will be considered as cancelling the funding *after* the `fundchannel_complete` succeeds. ([3778](https://github.com/ElementsProject/lightning/pull/3778))
 - JSON-RPC: `listfunds` 'outputs' now includes reserved outputs, designated as 'reserved' = true ([3764](https://github.com/ElementsProject/lightning/pull/3764))
 - JSON-RPC: `txprepare` now prepares transactions whose `nLockTime` is set to the tip blockheight, instead of using 0. `fundchannel` will use `nLockTime` set to the tip blockheight as well. ([3797](https://github.com/ElementsProject/lightning/pull/3797))
 - build: default compile output is prettier and much less verbose ([3686](https://github.com/ElementsProject/lightning/pull/3686))
 - config: the `plugin-disable` option now works even if specified before the plugin is found. ([3679](https://github.com/ElementsProject/lightning/pull/3679))
 - plugins: The `autoclean` plugin is no longer dynamic (you cannot manage it with the `plugin` RPC command anymore). ([3788](https://github.com/ElementsProject/lightning/pull/3788))
 - plugin: The `paystatus` output changed as a result of the payment flow rework ([3809](https://github.com/ElementsProject/lightning/pull/3809))

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON-RPC: the `legacypay` method from the pay plugin will be removed after `pay` proves stable ([3809](https://github.com/ElementsProject/lightning/pull/3809))

### Removed

 - protocol: support for optional fields of the reestablish message are now compulsory. ([3782](https://github.com/ElementsProject/lightning/pull/3782))

### Fixed

 - JSON-RPC: Reject some bad JSON at parsing. ([3761](https://github.com/ElementsProject/lightning/pull/3761))
 - JSON-RPC: The `feerate` parameters now correctly handle the standardness minimum when passed as `perkb`. ([3772](https://github.com/ElementsProject/lightning/pull/3772))
 - JSON-RPC: `listtransactions` now displays all txids as little endian ([3741](https://github.com/ElementsProject/lightning/pull/3741))
 - JSON-RPC: `pay` now respects maxfeepercent, even for tiny amounts. ([3693](https://github.com/ElementsProject/lightning/pull/3693))
 - JSON-RPC: `withdraw` and `txprepare` `feerate` can be a JSON number. ([3821](https://github.com/ElementsProject/lightning/pull/3821))
 - bitcoin: `lightningd` now always exits if the Bitcoin backend failed unexpectedly. ([3675](https://github.com/ElementsProject/lightning/pull/3675))
 - cli: Bash completion on `lightning-cli` now works again ([3719](https://github.com/ElementsProject/lightning/pull/3719))
 - config: we now take the `--commit-fee` parameter into account. ([3732](https://github.com/ElementsProject/lightning/pull/3732))
 - db: Fixed a failing assertion if we reconnect to a peer that we had a channel with before, and then attempt to insert the peer into the DB twice. ([3801](https://github.com/ElementsProject/lightning/pull/3801))
 - hsmtool: Make the password argument optional for `guesstoremote` and `dumpcommitments` sub-commands, as shown in our documentation and help text. ([3822](https://github.com/ElementsProject/lightning/pull/3822))
 - macOS: Build for macOS Catalina / Apple clang v11.0.3 fixed ([3756](https://github.com/ElementsProject/lightning/pull/3756))
 - protocol: Fixed a deviation from BOLT#2: if both nodes advertised `option_upfront_shutdown_script` feature: MUST include ... a zero-length `shutdown_scriptpubkey`. ([3816](https://github.com/ElementsProject/lightning/pull/3816))
 - wumbo: negotiate successfully with Eclair nodes. ([3712](https://github.com/ElementsProject/lightning/pull/3712))
 - plugin: `bcli` no longer logs a harmless warning about being unable to connect to the JSON-RPC interface. ([3857](https://github.com/ElementsProject/lightning/pull/3857))

### Security



## [0.8.2] - 2020-04-30: "A Scalable Ethereum Blockchain"

This release was named by @arowser.

### Added

 - pay: The `keysend` plugin implements the ability to receive spontaneous payments (keysend) ([3611](https://github.com/ElementsProject/lightning/pull/3611))
 - Plugin: the Bitcoin backend plugin API is now final. ([3620](https://github.com/ElementsProject/lightning/pull/3620))
 - Plugin: `htlc_accepted` hook can now offer a replacement onion `payload`. ([3611](https://github.com/ElementsProject/lightning/pull/3611))
 - Plugin: `feature_set` object added to `init` ([3612](https://github.com/ElementsProject/lightning/pull/3612))
 - Plugin: 'flag'-type option now available. ([3586](https://github.com/ElementsProject/lightning/pull/3586))
 - JSON API: New `getsharedsecret` command, which lets you compute a shared secret with this node knowing only a public point. This implements the BOLT standard of hashing the ECDH point, and is incompatible with ECIES. ([3490](https://github.com/ElementsProject/lightning/pull/3490))
 - JSON API: `large-channels` option to negotiate opening larger channels. ([3612](https://github.com/ElementsProject/lightning/pull/3612))
 - JSON API: New optional parameter to the `close` command to control the closing transaction fee negotiation back off step ([3390](https://github.com/ElementsProject/lightning/pull/3390))
 - JSON API: `connect` returns `features` of the connected peer on success. ([3612](https://github.com/ElementsProject/lightning/pull/3612))
 - JSON API: `listpeers` now has `receivable_msat` ([3572](https://github.com/ElementsProject/lightning/pull/3572))
 - JSON API: The fields "opening", "mutual_close", "unilateral_close", "delayed_to_us", "htlc_resolution" and "penalty" have been added to the `feerates` command. ([3570](https://github.com/ElementsProject/lightning/pull/3570))
 - JSON API: "htlc_timeout_satoshis" and "htlc_success_satoshis" fields have been added to the `feerates` command. ([3570](https://github.com/ElementsProject/lightning/pull/3570))
 - pyln now sends proper error on bad calls to plugin methods ([3640](https://github.com/ElementsProject/lightning/pull/3640))
 - devtools: The `onion` tool can now generate, compress and decompress onions for rendez-vous routing ([3557](https://github.com/ElementsProject/lightning/pull/3557))
 - doc: An FAQ was added, accessible at https://lightning.readthedocs.io/FAQ.html ([3551](https://github.com/ElementsProject/lightning/pull/3551))

### Changed

 - We now use a higher feerate for resolving onchain HTLCs and for penalty transactions ([3592](https://github.com/ElementsProject/lightning/pull/3592))
 - We now announce multiple addresses of the same type, if given. ([3609](https://github.com/ElementsProject/lightning/pull/3609))
 - pay: Improved the performance of the `pay`-plugin by limiting the `listchannels` when computing the shadow route. ([3617](https://github.com/ElementsProject/lightning/pull/3617))
 - JSON API: `invoice` `exposeprivatechannels` now includes explicitly named channels even if they seem like dead-ends. ([3633](https://github.com/ElementsProject/lightning/pull/3633))
 - Added workaround for lnd rejecting our commitment_signed when we send an update_fee after channel confirmed. ([3634](https://github.com/ElementsProject/lightning/pull/3634))
 - We now batch the requests for fee estimation to our Bitcoin backend. ([3570](https://github.com/ElementsProject/lightning/pull/3570))
 - We now get more fine-grained fee estimation from our Bitcoin backend. ([3570](https://github.com/ElementsProject/lightning/pull/3570))
 - Forwarding messages is now much faster (less inter-daemon traffic) ([3547](https://github.com/ElementsProject/lightning/pull/3547))
 - dependencies: We no longer depend on python2 which has reached end-of-life ([3552](https://github.com/ElementsProject/lightning/pull/3552))

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON API: `fundchannel_start` `satoshi` field really deprecated now (use `amount`). ([3603](https://github.com/ElementsProject/lightning/pull/3603))
 - JSON API: The "urgent", "slow", and "normal" field of the `feerates` command are now deprecated. ([3570](https://github.com/ElementsProject/lightning/pull/3570))
 - JSON API: Removed double wrapping of `rpc_command` payload in `rpc_command` JSON field. ([3560](https://github.com/ElementsProject/lightning/pull/3560))
 - Plugins: htlc_accepted_hook "failure_code" only handles simple cases now, use "failure_message". ([3472](https://github.com/ElementsProject/lightning/pull/3472))
 - Plugins: invoice_payment_hook "failure_code" only handles simple cases now, use "failure_message". ([3472](https://github.com/ElementsProject/lightning/pull/3472))

### Removed

 - JSON API: `listnodes` `globalfeatures` output (`features` since in 0.7.3). ([3603](https://github.com/ElementsProject/lightning/pull/3603))
 - JSON API: `listpeers` `localfeatures` and `globalfeatures` output (`features` since in 0.7.3). ([3603](https://github.com/ElementsProject/lightning/pull/3603))
 - JSON API: `peer_connected` hook `localfeatures` and `globalfeatures` output (`features` since in 0.7.3). ([3603](https://github.com/ElementsProject/lightning/pull/3603))
 - JSON API: `fundchannel` and `fundchannel_start` `satoshi` parameter removed (renamed to `amount` in 0.7.3). ([3603](https://github.com/ElementsProject/lightning/pull/3603))
 - JSON API: `close` `force` parameter removed (deprecated in 0.7.2.1) ([3603](https://github.com/ElementsProject/lightning/pull/3603))
 - JSON API: `sendpay` `description` parameter removed (renamed to `label` in 0.7.0). ([3603](https://github.com/ElementsProject/lightning/pull/3603))

### Fixed

 - Plugins: A crashing plugin will no longer cause a hook call to be delayed indefinitely ([3539](https://github.com/ElementsProject/lightning/pull/3539))
 - Plugins: setting an 'init' feature bit allows us to accept it from peers. ([3609](https://github.com/ElementsProject/lightning/pull/3609))
 - Plugins: if an option has a type int or bool, return the option as that type to the plugin's init ([3582](https://github.com/ElementsProject/lightning/pull/3582))
 - Plugins: Plugins no longer linger indefinitely if their process terminates ([3539](https://github.com/ElementsProject/lightning/pull/3539))
 - JSON API: Pending RPC method calls are now terminated if the handling plugin exits prematurely. ([3639](https://github.com/ElementsProject/lightning/pull/3639))
 - JSON API: `fundchannel_start` returns `amount` even when deprecated APIs are enabled. ([3603](https://github.com/ElementsProject/lightning/pull/3603))
 - JSON API: Passing 0 as minconf to withdraw allows you to use unconfirmed transaction outputs, even if explicitly passed as the `utxos` parameter ([3593](https://github.com/ElementsProject/lightning/pull/3593))
 - JSON API: `txprepare` doesn't crash lightningd anymore if you pass unconfirmed utxos ([3534](https://github.com/ElementsProject/lightning/pull/3534))
 - invoice: The invoice parser assumed that an amount without a multiplier was denominated in msatoshi instead of bitcoins. ([3636](https://github.com/ElementsProject/lightning/pull/3636))
 - pay: The `pay`-plugin was generating non-contiguous shadow routes ([3617](https://github.com/ElementsProject/lightning/pull/3617))
 - `pay` would crash on expired waits with tried routes ([3630](https://github.com/ElementsProject/lightning/pull/3630))
 - `pay` would crash when attempting to find cheaper route with exemptfee ([3630](https://github.com/ElementsProject/lightning/pull/3630))
 - Multiple definition of chainparams on Fedora (or other really recent gcc) ([3631](https://github.com/ElementsProject/lightning/pull/3631))
 - bcli now handles 0msat outputs in gettxout. ([3605](https://github.com/ElementsProject/lightning/pull/3605))
 - Fix assertion on reconnect if we fail to run openingd. ([3604](https://github.com/ElementsProject/lightning/pull/3604))
 - Use lightning-rfc #740 feespike margin factor of 2 ([3589](https://github.com/ElementsProject/lightning/pull/3589))
 - Always broadcast the latest close transaction at the end of the close fee negotiation, instead of sometimes broadcasting the peer's initial closing proposal. ([3556](https://github.com/ElementsProject/lightning/pull/3556))

### Security


## [0.8.1] - 2020-02-12: "Channel to the Moon"

This release named by Vasil Dimov @vasild.

### Added

 - Plugin: pluggable backends for Bitcoin data queries, default still bitcoind (using bitcoin-cli). ([3488](https://github.com/ElementsProject/lightning/pull/3488))
 - Plugin: Plugins can now signal support for experimental protocol extensions by registering featurebits for `node_announcement`s, the connection handshake, and for invoices. For now this is limited to non-dynamic plugins only ([3477](https://github.com/ElementsProject/lightning/pull/3477))
 - Plugin: 'plugin start' now restores initial umask before spawning the plugin process ([3375](https://github.com/ElementsProject/lightning/pull/3375))
 - JSON API: `fundchannel` and `fundchannel_start` can now accept an optional parameter, `push_msat`, which will gift that amount of satoshis to the peer at channel open. ([3369](https://github.com/ElementsProject/lightning/pull/3369))
 - JSON API: `waitanyinvoice` now supports a `timeout` parameter, which when set will cause the command to fail if unpaid after `timeout` seconds (can be 0). ([3449](https://github.com/ElementsProject/lightning/pull/3449))
 - Config: `--rpc-file-mode` sets permissions on the JSON-RPC socket. ([3437](https://github.com/ElementsProject/lightning/pull/3437))
 - Config: `--subdaemon` allows alternate subdaemons. ([3372](https://github.com/ElementsProject/lightning/pull/3372))
 - lightningd: Optimistic locking prevents instances from running concurrently against the same database, providing linear consistency to changes. ([3358](https://github.com/ElementsProject/lightning/pull/3358))
 - hsmd: Added fields to hsm_sign_remote_commitment_tx to allow complete validation by signing daemon. ([3363](https://github.com/ElementsProject/lightning/pull/3363))
 - Wallet: withdrawal transactions now sets nlocktime to the current tip. ([3465](https://github.com/ElementsProject/lightning/pull/3465))
 - elements: Added support for the dynafed block header format and elementsd >=0.18.1 ([3440](https://github.com/ElementsProject/lightning/pull/3440))

### Changed

 - JSON API: The hooks `db_write`, `invoice_payment`, and `rpc_command` now accept `{ "result": "continue" }` to mean "do default action". ([3475](https://github.com/ElementsProject/lightning/pull/3475))
 - Plugin: Multiple plugins can now register for the htlc_accepted hook. ([3489](https://github.com/ElementsProject/lightning/pull/3489))
 - JSON API: `listforwards` now shows `out_channel` even if we couldn't forward.
 - JSON API: `funchannel_cancel`: only the opener of a fundchannel can cancel the channel open ([3336](https://github.com/ElementsProject/lightning/pull/3336))
 - JSON API: `sendpay` optional `msatoshi` param for non-MPP (if set), must be the exact amount sent to the final recipient. ([3470](https://github.com/ElementsProject/lightning/pull/3470))
 - JSON API: `waitinvoice` now returns error code 903 to designate that the invoice expired during wait, instead of the previous -2 ([3441](https://github.com/ElementsProject/lightning/pull/3441))
 - JSON_API: The `connect` command now returns its own error codes instead of a generic -1. ([3397](https://github.com/ElementsProject/lightning/pull/3397))
 - Plugin: `notify_sendpay_success` and `notify_sendpay_failure` are now always called, even if there is no command waiting on the result. ([3405](https://github.com/ElementsProject/lightning/pull/3405))
 - hsmtool: `hsmtool` now creates its backup copy in the same directory as the original `hsm_secret` file. ([3409](https://github.com/ElementsProject/lightning/pull/3409))
 - JSON API: `invoice` `exposeprivatechannels` can specify exact channel candidates. ([3351](https://github.com/ElementsProject/lightning/pull/3351))
 - JSON API: `db_write` new field `data_version` which contains a numeric transaction counter. ([3358](https://github.com/ElementsProject/lightning/pull/3358))
 - JSON API: `plugin stop` result is now accessible using the `result` key instead of the empty ('') key. ([3374](https://github.com/ElementsProject/lightning/pull/3374))
 - lightning-cli: specifying `--rpc-file` (without `--network`) has been restored. ([3353](https://github.com/ElementsProject/lightning/pull/3353))

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON API: The hook `db_write` returning `true`: use `{ "result": "continue" }`. ([3475](https://github.com/ElementsProject/lightning/pull/3475))
 - JSON API: The hook `invoice_payment` returning `{}`: use `{ "result": "continue" }`. ([3475](https://github.com/ElementsProject/lightning/pull/3475))
 - JSON API: The hook `rpc_command` returning `{"continue": true}`: use `{ "result": "continue" }`. ([3475](https://github.com/ElementsProject/lightning/pull/3475))
 - JSON API: `plugin stop` result with an empty ("") key: use "result". ([3374](https://github.com/ElementsProject/lightning/pull/3374))


### Removed

 - Plugin: Relative plugin paths are not relative to startup (deprecated v0.7.2.1) ([3471](https://github.com/ElementsProject/lightning/pull/3471))
 - JSON API: Dummy fields in listforwards (deprecated v0.7.2.1) ([3471](https://github.com/ElementsProject/lightning/pull/3471))

### Fixed

 - Doc: Corrected and expanded `lightning-listpeers.7` documentation. ([3497](https://github.com/ElementsProject/lightning/pull/3497))
 - Doc: Fixed factual errors in `lightning-listchannels.7` documentation. ([3494](https://github.com/ElementsProject/lightning/pull/3494))
 - Protocol: Corner case where channel could become unusable (https://github.com/lightningnetwork/lightning-rfc/issues/728) ([3500](https://github.com/ElementsProject/lightning/pull/3500))
 - Plugins: Dynamic C plugins can now be managed when lightningd is up ([3480](https://github.com/ElementsProject/lightning/pull/3480))
 - Doc: `connect`: clarified failure problems and usage. ([3459](https://github.com/ElementsProject/lightning/pull/3459))
 - Doc: `fundchannel`: clarify that we automatically `connect`s if your node knows how. ([3459](https://github.com/ElementsProject/lightning/pull/3459))
 - Protocol: Now correctly reject "fees" paid when we're the final hop (lightning-rfc#711) ([3474](https://github.com/ElementsProject/lightning/pull/3474))
 - JSON API: `txprepare` no longer crashes when more than two outputs are specified ([3384](https://github.com/ElementsProject/lightning/pull/3384))
 - Pyln: now includes the "jsonrpc" field to jsonrpc2 requests ([3442](https://github.com/ElementsProject/lightning/pull/3442))
 - Plugin: `pay` now detects a previously non-permanent error (`final_cltv_too_soon`) that has been merged into a permanent error (`incorrect_or_unknown_payment_details`), and retries. ([3376](https://github.com/ElementsProject/lightning/pull/3376))
 - JSON API: The arguments for `createonion` are now checked to ensure they fit in the onion packet. ([3404](https://github.com/ElementsProject/lightning/pull/3404))
 - TOR: We don't send any further request if the return code of connect is not zero or error. ([3408](https://github.com/ElementsProject/lightning/pull/3408))
 - Build: Developer mode compilation on FreeBSD. ([3344](https://github.com/ElementsProject/lightning/pull/3344))
 - Protocol: We now reject invoices which ask for sub-millisatoshi amounts ([3481](https://github.com/ElementsProject/lightning/pull/3481))

### Security

## [0.8.0] - 2019-12-16: "Blockchain Good, Orange Coin Bad"

This release was named by Michael Schmoock @m-schmoock.

### Added

 - JSON API: Added `createonion` and `sendonion` JSON-RPC methods allowing the implementation of custom protocol extensions that are not directly implemented in c-lightning itself. ([3260](https://github.com/ElementsProject/lightning/pull/3260))
 - JSON API: `listinvoices` now displays the payment preimage if the invoice was paid. ([3295](https://github.com/ElementsProject/lightning/pull/3295))
 - JSON API: `listpeers` channels now include `close_to` and `close_to_addr` iff a `close_to` address was specified at channel open ([3223](https://github.com/ElementsProject/lightning/pull/3223))
 - The new `pyln-testing` package now contains the testing infrastructure so it can be reused to test against c-lightning in external projects ([3218](https://github.com/ElementsProject/lightning/pull/3218))
 - config: configuration files now support `include`. ([3268](https://github.com/ElementsProject/lightning/pull/3268))
 - options: Allow the Tor inbound service port differ from 9735 ([3155](https://github.com/ElementsProject/lightning/pull/3155))
 - options: Persistent Tor address support ([3155](https://github.com/ElementsProject/lightning/pull/3155))
 - plugins: A new plugin hook, `rpc_command` allows a plugin to take over `lightningd` for any RPC command. ([2925](https://github.com/ElementsProject/lightning/pull/2925))
 - plugins: Allow the `accepter` to specify an upfront_shutdown_script for a channel via a `close_to` field in the openchannel hook result ([3280](https://github.com/ElementsProject/lightning/pull/3280))
 - plugins: Plugins may now handle modern TLV-style payloads via the `htlc_accepted` hook ([3260](https://github.com/ElementsProject/lightning/pull/3260))
 - plugins: libplugin now supports writing plugins which register to hooks ([3317](https://github.com/ElementsProject/lightning/pull/3317))
 - plugins: libplugin now supports writing plugins which register to notifications ([3317](https://github.com/ElementsProject/lightning/pull/3317))
 - protocol: Payment amount fuzzing is restored, but through shadow routing. ([3212](https://github.com/ElementsProject/lightning/pull/3212))
 - protocol: We now signal the network we are running on at init. ([3300](https://github.com/ElementsProject/lightning/pull/3300))
 - protocol: can now send and receive TLV-style onion messages. ([3335](https://github.com/ElementsProject/lightning/pull/3335))
 - protocol: can now send and receive BOLT11 payment_secrets. ([3335](https://github.com/ElementsProject/lightning/pull/3335))
 - protocol: can now receive basic multi-part payments. ([3335](https://github.com/ElementsProject/lightning/pull/3335))
 - JSON RPC: low-level commands sendpay and waitsendpay can now be used to manually send multi-part payments. ([3335](https://github.com/ElementsProject/lightning/pull/3335))
 - quirks: Workaround LND's `reply_channel_range` issues instead of sending error. ([3264](https://github.com/ElementsProject/lightning/pull/3264))
 - tools: A new command, `guesstoremote`, is added to the hsmtool. It is meant to be used to recover funds after an unilateral close of a channel with `option_static_remotekey` enabled. ([3292](https://github.com/ElementsProject/lightning/pull/3292))

### Changed

:warning: The default network and the default location of the lightning home directory changed. Please make sure that the configuration, key file and database are moved into the network-specific subdirectory.

 - config: Default network (new installs) is now bitcoin, not testnet. ([3268](https://github.com/ElementsProject/lightning/pull/3268))
 - config: Lightning directory, plugins and files moved into `<network>/` subdir ([3268](https://github.com/ElementsProject/lightning/pull/3268))
 - JSON API: The `fundchannel` command now tries to connect to the peer before funding the channel, no need to `connect` before `fundchannel` if an address for the peer is known ([3314](https://github.com/ElementsProject/lightning/pull/3314))
 - JSON API: `htlc_accepted` hook has `type` (currently `legacy` or `tlv`) and other fields directly inside `onion`. ([3167](https://github.com/ElementsProject/lightning/pull/3167))
 - JSON API: `lightning_` prefixes removed from subdaemon names, including in listpeers `owner` field. ([3241](https://github.com/ElementsProject/lightning/pull/3241))
 - JSON API: `listconfigs` now structures plugins and include their options ([3283](https://github.com/ElementsProject/lightning/pull/3283))
 - JSON API: the `raw_payload` now includes the first byte, i.e., the realm byte, of the payload as well. This allows correct decoding of a TLV payload in the plugins. ([3261](https://github.com/ElementsProject/lightning/pull/3261))
 - logging: formatting made uniform: [NODEID-]SUBSYSTEM: MESSAGE ([3241](https://github.com/ElementsProject/lightning/pull/3241))
 - options: `config` and `<network>/config` read by default. ([3268](https://github.com/ElementsProject/lightning/pull/3268))
 - options: log-level can now specify different levels for different subsystems. ([3241](https://github.com/ElementsProject/lightning/pull/3241))
 - protocol: The TLV payloads for the onion packets are no longer considered an experimental feature and generally available. ([3260](https://github.com/ElementsProject/lightning/pull/3260))
 - quirks: We'll now reconnect and retry if we get an error on an established channel. This works around lnd sending error messages that may be non-fatal. ([3340](https://github.com/ElementsProject/lightning/pull/3340))

:warning: If you don't have a config file, you now may need to specify the network to `lightning-cli` ([3268](https://github.com/ElementsProject/lightning/pull/3268))

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

 - JSON API: `listconfigs` duplicated "plugin" paths ([3283](https://github.com/ElementsProject/lightning/pull/3283))
 - JSON API: `htlc_accepted` hook `per_hop_v0` object deprecated, as is `short_channel_id` for the final hop. ([3167](https://github.com/ElementsProject/lightning/pull/3167))

### Removed

 - JSON: `listpays` won't shown payments made via sendpay without a bolt11 string, or before 0.7.0. ([3309](https://github.com/ElementsProject/lightning/pull/3309))

### Fixed

 - JSON API: #3231 `listtransactions` crash ([3256](https://github.com/ElementsProject/lightning/pull/3256))
 - JSON API: `listconfigs` appends '...' to truncated config options. ([3268](https://github.com/ElementsProject/lightning/pull/3268))
 - `pyln-client` now handles unicode characters in JSON-RPC requests and responses correctly. ([3018](https://github.com/ElementsProject/lightning/pull/3018))
 - bitcoin: If bitcoind goes backwards (e.g. reindex) refuse to start (unless forced with --rescan). ([3274](https://github.com/ElementsProject/lightning/pull/3274))
 - bug: `gossipd` crash on huge number of unknown channels. ([3273](https://github.com/ElementsProject/lightning/pull/3273))
 - gossip: No longer discard most `node_announcements` (fixes #3194) ([3262](https://github.com/ElementsProject/lightning/pull/3262))
 - options: We disable all dns even on startup the scan for bogus dns servers, if `--always-use-proxy` is set true ([3251](https://github.com/ElementsProject/lightning/pull/3251))
 - protocol: "Bad commitment signature" closing channels when we sent back-to-back update_fee messages across multiple reconnects. ([3329](https://github.com/ElementsProject/lightning/pull/3329))
 - protocol: Unlikely corner case is simultanous HTLCs near balance limits fixed. ([3286](https://github.com/ElementsProject/lightning/pull/3286))

### Security

## [0.7.3] - 2019-10-18: "Bitcoin's Proof of Stake"

This release was named by @trueptolemy.

### Added

- DB: lightningd now supports different SQL backends, instead of the default which is sqlite3. Adds a PostgresSQL driver
- elements: Add support of Liquid-BTC on elements
- JSON API: `close` now accepts an optional parameter `destination`, to which the to-local output will be sent.
- JSON API: `txprepare` and `withdraw` now accept an optional parameter `utxos`, a list of utxos to include in the prepared transaction
- JSON API: `listfunds` now lists a blockheight for confirmed transactions, and has `connected` and `state` fields for channels, like `listpeers`.
- JSON API: `fundchannel_start` now includes field `scriptpubkey`
- JSON API: New method `listtransactions`
- JSON API: `signmessage` will now create a signature from your node on a message; `checkmessage` will verify it.
- JSON API: `fundchannel_start` now accepts an optional parameter `close_to`, the address to which these channel funds should be sent to on close. Returns `using_close_to` if will use.
- Plugin: new notifications `sendpay_success` and `sendpay_failure`.
- Protocol: nodes now announce features in `node_announcement` broadcasts.
- Protocol: we now offer `option_gossip_queries_ex` for finegrained gossip control.
- Protocol: we now retransmit `funding_locked` upon reconnection while closing if there was no update
- Protocol: no longer ask for `initial_routing_sync` (only affects ancient peers).
- bolt11: support for parsing feature bits (field `9`).
- Wallet: we now support the encryption of the BIP32 master seed (a.k.a. `hsm_secret`).
- pylightning: includes implementation of handshake protocol

### Changed

- Build: Now requires [`gettext`](https://www.gnu.org/software/gettext/)
- JSON API: The parameter `exclude` of `getroute` now also support node-id.
- JSON API: `txprepare` now uses `outputs` as parameter other than `destination` and `satoshi`
- JSON API: `fundchannel_cancel` is extended to work before funding broadcast.
- JSON-API: `pay` can exclude error nodes if the failcode of `sendpay` has the NODE bit set
- JSON API: The `plugin` command now returns on error. A timeout of 20 seconds is added to `start` and `startdir` subcommands at the end of which the plugin is errored if it did not complete the handshake with `lightningd`.
- JSON API: The `plugin` command does not allow to start static plugins after `lightningd` startup anymore.
- Protocol: We now push our own gossip to all peers, independent of their filter.
- Protocol: Now follows spec in responses to short channel id queries on unknown chainhashes
- Tor: We default now with autotor to generate if possible temporary ED25519-V3 onions.  You can use new option `enable-autotor-v2-mode` to fallback to V2 RSA1024 mode.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for changes.

- JSON API: `fundchannel` now uses `amount` as the parameter name to replace `satoshi`
- JSON API: `fundchannel_start` now uses `amount` as the parameter name to replace `satoshi`
- JSON API: `listpeers` and `listnodes` fields `localfeatures` and `globalfeatures` (now just `features`).
- Plugin: `peer_connected` hook fields `localfeatures` and `globalfeatures` (now just `features`).

### Removed

- JSON API: `short_channel_id` parameters in JSON commands with `:` separators (deprecated since 0.7.0).
- JSON API: `description` parameters in `pay` and `sendpay` (deprecated since 0.7.0).
- JSON API: `description` output field in `waitsendpay` and `sendpay` (deprecated since 0.7.0).
- JSON API: `listpayments` (deprecated since 0.7.0).

### Fixed

- Fixed bogus "Bad commit_sig signature" which caused channel closures when reconnecting after updating fees under simultaneous bidirectional traffic.
- Relative `--lightning_dir` is now working again.
- Build: MacOS now builds again (missing pwritev).

### Security



## [0.7.2.1] - 2019-08-19: "Nakamoto's Pre-approval by US Congress"

This release was named by Antoine Poinsot @darosior.

(Technically a .1 release, as it contains last-minute fixes after 0.7.2 was tagged)

### Added

- JSON API: a new command `plugin` allows one to manage plugins without restarting `lightningd`.
- Plugin: a new boolean field can be added to a plugin manifest, `dynamic`. It allows a plugin to tell if it can be started or stopped "on-the-fly".
- Plugin: a new boolean field is added to the `init`'s `configuration`, `startup`. It allows a plugin to know if it has been started on `lightningd` startup.
- Plugin: new notifications `invoice_payment`, `forward_event` and `channel_opened`.
- Protocol: `--enable-experimental-features` adds gossip query extensions
  aka https://github.com/lightningnetwork/lightning-rfc/pull/557
- contrib: new `bootstrap-node.sh` to connect to random mainnet nodes.
- JSON API: `listfunds` now returns also `funding_output` for `channels`
- Plugin: plugins can now suggest `lightning-cli` default to -H for responses.
- Lightningd: add support for `signet` networks using the `--network=signet` or `--signet` startup option

### Changed

- Build: now requires `python3-mako` to be installed, i.e. `sudo apt-get install python3-mako`
- JSON API: `close` optional arguments have changed: it now defaults to unilateral close after 48 hours.
- Plugin: if the config directory has a `plugins` subdirectory, those are loaded.
- lightningd: check bitcoind version when setup topology and confirm the version not older than v0.15.0.
- Protocol: space out reconnections on startup if we have more than 5 peers.
- JSON API: `listforwards` includes the 'payment_hash' field.
- Plugin: now plugins always run from the `lightning-dir` for easy local storage.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for
changes.

- Plugin: using startup-relative paths for `plugin` and `plugin-dir`: they're now relative to `lightning-dir`.
- JSON API: `listforwards` removed dummy (zero) fields for `out_msat`, `fee_msat`, `in_channel` and `out_channel` if unknown (i.e. deleted from db, or `status` is `local-failed`.

### Removed

### Fixed

- Plugin: `pay` no longer crashes on timeout.
- Plugin: `disconnect` notifier now called if remote side disconnects.
- channeld: ignore, and simply try reconnecting if lnd sends "sync error".
- Protocol: we now correctly ignore unknown odd messages.
- wallet: We will now backfill blocks below our wallet start height on demand when we require them to verify gossip messages. This fixes an issue where we would not remove channels on spend that were opened below that start height because we weren't tracking the funding output.
- Detect when we're still syncing with bitcoin network: don't send or receive
  HTLCs or allow `fundchannel`.
- Rare onchaind error where we don't recover our own unilateral close with multiple same-preimage HTLCs fixed.

### Security

## [0.7.1] - 2019-06-29: "The Unfailing Twitter Consensus Algorithm"

This release was named by (C-Lightning Core Team member) Lisa Neigut @niftynei.

### Added

- Protocol: we now enforce `option_upfront_shutdown_script` if a peer negotiates it.
- JSON API: New command `setchannelfee` sets channel specific routing fees.
- JSON API: new withdraw methods `txprepare`, `txsend` and `txdiscard`.
- JSON API: add three new RPC commands: `fundchannel_start`, `fundchannel_complete` and `fundchannel_cancel`. Allows a user to initiate and complete a channel open using funds that are in a external wallet.
- Plugin: new hooks `db_write` for intercepting database writes, `invoice_payment` for intercepting invoices before they're paid, `openchannel` for intercepting channel opens, and `htlc_accepted` to decide whether to resolve, reject or continue an incoming or forwarded payment..
- Plugin: new notification `warning` to report any `LOG_UNUSUAL`/`LOG_BROKEN` level event.
- Plugin: Added a default plugin directory : `lightning_dir/plugins`. Each plugin directory it contains will be added to lightningd on startup.
- Plugin: the `connected` hook can now send an `error_message` to the rejected peer.
- JSON API: `newaddr` outputs `bech32` or `p2sh-segwit`, or both with new `all` parameter (#2390)
- JSON API: `listpeers` status now shows how many confirmations until channel is open (#2405)
- Config: Adds parameter `min-capacity-sat` to reject tiny channels.
- JSON API: `listforwards` now includes the time an HTLC was received and when it was resolved. Both are expressed as UNIX timestamps to facilitate parsing (Issue [#2491](https://github.com/ElementsProject/lightning/issues/2491), PR [#2528](https://github.com/ElementsProject/lightning/pull/2528))
- JSON API: `listforwards` now includes the local_failed forwards with failcode (Issue [#2435](https://github.com/ElementsProject/lightning/issues/2435), PR [#2524](https://github.com/ElementsProject/lightning/pull/2524))
- DB: Store the signatures of channel announcement sent from remote peer into DB, and init channel with signatures from DB directly when reenable the channel.
(Issue [#2409](https://github.com/ElementsProject/lightning/issues/2409))
- JSON API: `listchannels` has new fields `htlc_minimum_msat` and `htlc_maximum_msat`.

### Changed

- Gossip: we no longer compact the `gossip_store` file dynamically, due to lingering bugs.  Restart if it gets too large.
- Protocol: no longer ask for entire gossip flood from peers, unless we're missing gossip.
- JSON API: `invoice` expiry defaults to 7 days, and can have s/m/h/d/w suffixes.
- Config: Increased default amount for minimal channel capacity from 1k sat to 10k sat.
- JSON API: A new parameter is added to `fundchannel`, which now accepts an utxo array to use to fund the channel.
- Build: Non-developer builds are now done with "-Og" optimization.
- JSON API: `pay` will no longer return failure until it is no longer retrying; previously it could "timeout" but still make the payment.
- JSON API: the command objects that `help` outputs now contain a new string field : `category` (can be "bitcoin", "channels", "network", "payment", "plugins", "utility", "developer" for native commands, or any other new category set by a plugin).
- Plugin: a plugin can now set the category of a newly created RPC command. This possibility has been added to libplugin.c and pylightning.
- lightning-cli: the human readable help is now more human and more readable : commands are sorted alphabetically and ordered by categories.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for
changes.

- JSON API: `newaddr` output field `address`: use `bech32` or `p2sh-segwit` instead.

### Removed

- JSON RPC: `global_features` and `local_features` fields and `listchannels`' `flags` field.  (Deprecated since 0.6.2).
- pylightning: Remove RPC support for c-lightning before 0.6.3.

### Fixed

- Protocol: reconnection during closing negotiation now supports
  `option_data_loss_protect` properly.
- `--bind-addr=<path>` fixed for nodes using local sockets (eg. testing).
- Unannounced local channels were forgotten for routing on restart until reconnection occurred.
- lightning-cli: arguments containing `"` now succeed, rather than causing JSON errors.
- Protocol: handle lnd sending more messages before `reestablish`; don't fail channel, and handle older lnd's spurious empty commitments.
- Fixed `fundchannel` crash when we have many UTXOs and we skip unconfirmed ones.
- lightningd: fixed occasional hang on `connect` when peer had sent error.
- JSON RPC: `decodeinvoice` and `pay` now handle unknown invoice fields properly.
- JSON API: `waitsendpay` (PAY_STOPPED_RETRYING) error handler now returns valid JSON
- protocol: don't send multiple identical feerate changes if we want the feerate higher than we can afford.
- JSON API: `stop` now only returns once lightningd has released all resources.

### Security

- Fixes CVE-2019-12998 ([Full Disclosure](https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-September/002174.html)).

## [0.7.0] - 2019-02-28: "Actually an Altcoin"

This release was named by Mark Beckwith @wythe.

### Added

- plugins: fully enabled, and ready for you to write some!
- plugins: `pay` is now a plugin.
- protocol: `pay` will now use routehints in invoices if it needs to.
- build: reproducible source zipfile and Ubuntu 18.04.1 build.
- JSON API: New command `paystatus` gives detailed information on `pay` commands.
- JSON API: `getroute`, `invoice`, `sendpay` and `pay` commands `msatoshi`
  parameter can have suffixes `msat`, `sat` (optionally with 3 decimals) or `btc`
  (with 1 to 11 decimal places).
- JSON API: `fundchannel` and `withdraw` commands `satoshi`
  parameter can have suffixes `msat` (must end in `000`), `sat` or `btc`
  (with 1 to 8 decimal places).
- JSON API: `decodepay`, `getroute`, `sendpay`, `pay`, `listpeers`, `listfunds`, `listchannels` and
  all invoice commands now return an `amount_msat` field which has an `msat` suffix.
- JSON API: `listfunds` `channels` now has `_msat` fields for each existing raw amount field, with `msat` suffix.
- JSON API: `waitsendpay` now has an `erring_direction` field.
- JSON API: `listpeers` now has a `direction` field in `channels`.
- JSON API: `listchannels` now takes a `source` option to filter by node id.
- JSON API: `getroute` `riskfactor` argument is simplified; `pay` now defaults to setting it to 10.
- JSON API: `sendpay` now takes a `bolt11` field, and it's returned in `listpayments` and `waitsendpay`.
- JSON API: `fundchannel` and `withdraw` now have a new parameter `minconf` that limits coinselection to outputs that have at least `minconf` confirmations (default 1). (#2380)
- JSON API: `listfunds` now displays addresses for all outputs owned by the wallet (#2387)
- JSON API: `waitsendpay` and `sendpay` output field `label` as specified by `sendpay` call.
- JSON API: `listpays` command for higher-level payment view than `listpayments`, especially important with multi-part-payments coming.
- JSON API: `listpayments` is now `listsendpays`.
- lightning-cli: `help <cmd>` finds man pages even if `make install` not run.
- pylightning: New class 'Millisatoshi' can be used for JSON API, and new '_msat' fields are turned into this on reading.

### Changed

- protocol: `option_data_loss_protect` is now enabled by default.
- JSON API: The `short_channel_id` separator has been changed to be `x` to match the specification.
- JSON API: `listpeers` now includes `funding_allocation_msat`, which returns a map of the amounts initially funded to the channel by each peer, indexed by channel id.
- JSON API: `help` with a `command` argument gives a JSON array, like other commands.
- JSON API: `sendpay` `description` parameter is renamed `label`.
- JSON API: `pay` now takes an optional `label` parameter for labelling payments, in place of never-used `description`.
- build: we'll use the system libbase58 and libsodium if found suitable.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for
changes.

We recommend that you transition to the reading the new JSON `_msat`
fields for your own sanity checking, and that you similarly
provide appropriate suffixes for JSON input fields.

- JSON API: `short_channel_id` fields in JSON commands with `:` separators (use `x` instead).
- JSON API: `pay` `description` is deprecated, as is support for BOLT11 strings using `h`.
- JSON API: `sendpay` parameter `description` and `waitsendpay` and `sendpay` output fields `description` (now `label`).
- JSON API: `listpayments` has been deprecated (you probably want `listpays`)

### Removed

- JSON API: the `waitsendpay` command error return no longer includes `channel_update`

### Fixed

- Protocol: handling `query_channel_range` for large numbers of blocks
  (eg. 4 billion) was slow due to a bug.
- Fixed occasional deadlock with peers when exchanging huge amounts of gossip.
- Fixed a crash when running in daemon-mode due to db filename overrun (#2348)
- Handle lnd sending premature 'funding_locked' message when we're expected 'reestablish';
  we used to close channel if this happened.
- Cleanup peers that started opening a channel, but then disconnected. These
  would leave a dangling entry in the DB that would cause this peer to be
  unable to connect. (PR #2371)
- You can no longer make giant unpayable "wumbo" invoices.
- CLTV of total route now correctly evaluated when finding best route.
- `riskfactor` arguments to `pay` and `getroute` now have an effect.
- Fixed the version of bip32 private_key to BIP32_VER_MAIN_PRIVATE: we used
  BIP32_VER_MAIN_PRIVATE for bitcoin/litecoin mainnet, and BIP32_VER_TEST_PRIVATE
  for others. (PR #2436)

### Security

## [0.6.3] - 2019-01-09: "The Smallblock Conspiracy"

This release was named by @molxyz and [@ctrlbreak](https://twitter.com/ctrlbreak).

### Added

- JSON API: New command `check` checks the validity of a JSON API call without running it.
- JSON API: `getinfo` now returns `num_peers` `num_pending_channels`,
  `num_active_channels` and `num_inactive_channels` fields.
- JSON API: use `\n\n` to terminate responses, for simplified parsing (pylightning now relies on this)
- JSON API: `fundchannel` now includes an `announce` option, when false it will keep channel private. Defaults to true.
- JSON API: `listpeers`'s `channels` now includes a `private` flag to indicate if channel is announced or not.
- JSON API: `invoice` route hints may now include private channels if you have no public ones, unless new option `exposeprivatechannels` is false.
- Plugins: experimental plugin support for `lightningd`, including option passthrough and JSON-RPC passthrough.
- Protocol: we now support features `option_static_remotekey` and `gossip_queries_ex` for peers.

### Changed

- JSON API: `pay` and `decodepay` accept and ignore `lightning:` prefixes.
- pylightning: Allow either keyword arguments or positional arguments.
- JSON-RPC: messages are now separated by 2 consecutive newlines.
- JSON-RPC: `jsonrpc`:`2.0` now included in json-rpc command calls. complies with spec.

### Deprecated

Note: You should always set `allow-deprecated-apis=false` to test for
changes.

- pylightning: Support for pre-2-newline JSON-RPC (<= 0.6.2 lightningd) is deprecated.

### Removed

- option_data_loss_protect is now only offered if EXPERIMENTAL_FEATURES is enabled, since it seems incompatible with lnd and has known bugs.

### Fixed

- JSON API: uppercase invoices now parsed correctly (broken in 0.6.2).
- JSON API: commands are once again read even if one hasn't responded yet (broken in 0.6.2).
- Protocol: allow lnd to send `update_fee` before `funding_locked`.
- Protocol: fix limit on how much funder can send (fee was 1000x too small)
- Protocol: don't send invalid onion errors if peer says onion was bad.
- Protocol: don't crash when peer sends a 0-block-expiry HTLC.
- pylightning: handle multiple simultanous RPC replies reliably.
- build: we use `--prefix` as handed to `./configure`

### Security


## [0.6.2] - 2018-10-20: "The Consensus Loving Nasal Daemon"

This release was named by practicalswift.

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

- JSON API: the optional 'seed' parameter to `getroute` was removed.

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

This release was named by ZmnSCPxj.

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

This release was named by Fabrice Drouin.

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
4. [0.4] - 2016-08-19: "Wright's Cryptographic Proof" (named by Christian Decker)
5. [0.5] - 2016-10-19: "Bitcoin Savings & Trust Daily Interest" (named by Glenn Willen)
6. [0.5.1] - 2016-10-21
7. [0.5.2] - 2016-11-21: "Bitcoin Savings & Trust Daily Interest II"

[23.11]: https://github.com/ElementsProject/lightning/releases/tag/v23.11
[23.05]: https://github.com/ElementsProject/lightning/releases/tag/v23.05
[23.02.1]: https://github.com/ElementsProject/lightning/releases/tag/v23.02.1
[23.02]: https://github.com/ElementsProject/lightning/releases/tag/v23.02
[0.12.0]: https://github.com/ElementsProject/lightning/releases/tag/v0.12.0
[0.11.2]: https://github.com/ElementsProject/lightning/releases/tag/v0.11.2
[0.11.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.11.1
[0.11.0.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.11.0.1
[0.10.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.10.1
[0.10.0]: https://github.com/ElementsProject/lightning/releases/tag/v0.10.0
[0.9.2]: https://github.com/ElementsProject/lightning/releases/tag/v0.9.2
[0.9.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.9.1
[0.9.0]: https://github.com/ElementsProject/lightning/releases/tag/v0.9.0
[0.8.2]: https://github.com/ElementsProject/lightning/releases/tag/v0.8.2
[0.8.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.8.1
[0.8.0]: https://github.com/ElementsProject/lightning/releases/tag/v0.8.0
[0.7.3]: https://github.com/ElementsProject/lightning/releases/tag/v0.7.3
[0.7.2.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.7.2.1
[0.7.1]: https://github.com/ElementsProject/lightning/releases/tag/v0.7.1
[0.7.0]: https://github.com/ElementsProject/lightning/releases/tag/v0.7.0
[0.6.3]: https://github.com/ElementsProject/lightning/releases/tag/v0.6.3
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
