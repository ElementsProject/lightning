# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.9.0rc1] - 2020-07-15

### Added

 - mpp: The adaptive multi-part payment modifier will split payments that are failing due to their size into smaller parts, and re-attempted. ([3809](https://github.com/ElementsProject/lightning/pull/3809))
 - mpp: The presplit modifier splits large payments into 10k satoshi parts to maximize chances of performing the payment and to obfuscate the overall amount being sent. ([3809](https://github.com/ElementsProject/lightning/pull/3809))
 - JSON-API: `txprepare` returns a psbt version of the created transaction ([3825](https://github.com/ElementsProject/lightning/pull/3825))
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

### Changed

 - JSON-RPC: `fundchannel_cancel` no longer requires its undocumented `channel_id` argument after `fundchannel_complete`. ([3787](https://github.com/ElementsProject/lightning/pull/3787))
 - JSON-RPC: `fundchannel_cancel` will now succeed even when executed while a `fundchannel_complete` is ongoing; in that case, it will be considered as cancelling the funding *after* the `fundchannel_complete` succeeds. ([3778](https://github.com/ElementsProject/lightning/pull/3778))
 - JSON-RPC: `listfunds` 'outputs' now includes reserved outputs, designated as 'reserved' = true ([3764](https://github.com/ElementsProject/lightning/pull/3764))
 - JSON-RPC: `txprepare` now prepares transactions whose `nLockTime` is set to the tip blockheight, instead of using 0. `fundchannel` will use `nLockTime` set to the tip blockheight as well. ([3797](https://github.com/ElementsProject/lightning/pull/3797))
 - build: default compile output is prettier and much less verbose ([3686](https://github.com/ElementsProject/lightning/pull/3686))
 - config: the `plugin-disable` option now works even if specified before the plugin is found. ([3679](https://github.com/ElementsProject/lightning/pull/3679))
 - plugins: The `autoclean` plugin is no longer dynamic (you cannot manage it with the `plugin` RPC command anymore). ([3788](https://github.com/ElementsProject/lightning/pull/3788))


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

[0.9.0rc1]: https://github.com/ElementsProject/lightning/releases/tag/v0.9.0rc1
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
