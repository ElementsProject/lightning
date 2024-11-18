---
title: "Hooks"
slug: "hooks"
hidden: false
createdAt: "2023-02-03T08:57:58.166Z"
updatedAt: "2023-02-21T15:08:30.254Z"
---
Hooks allow a plugin to define custom behavior for `lightningd` without having to modify the Core Lightning source code itself. A plugin declares that it'd like to be consulted on what to do next for certain events in the daemon. A hook can then decide how `lightningd` should
react to the given event.

When hooks are registered, they can optionally specify "before" and "after" arrays of plugin names, which control what order they will be called in.  If a plugin name is unknown, it is ignored, otherwise if the hook calls cannot be ordered to satisfy the specifications of all plugin hooks, the plugin registration will fail.

The call semantics of the hooks, i.e., when and how hooks are called, depend on the hook type. Most hooks are currently set to `single`-mode. In this mode only a single plugin can register the hook, and that plugin will get called for each event of that type. If a second plugin attempts to register the hook it gets killed and a corresponding log entry will be added to the logs.

In `chain`-mode multiple plugins can register for the hook type and they are called in any order they are loaded (i.e. cmdline order first, configuration order file second: though note that the order of plugin directories is implementation-dependent), overridden only by `before` and `after` requirements the plugin's hook registrations specify. Each plugin can then handle the event or defer by returning a `continue` result like the following:

```json
{
  "result": "continue"
}
```



The remainder of the response is ignored and if there are any more plugins that have registered the hook the next one gets called. If there are no more plugins then the internal handling is resumed as if no hook had been called. Any other result returned by a plugin is considered an exit from the chain. Upon exit no more plugin hooks are called for the current event, and
the result is executed. Unless otherwise stated all hooks are `single`-mode.

Hooks and notifications are very similar, however there are a few key differences:

- Notifications are asynchronous, i.e., `lightningd` will send the notifications but not wait for the plugin to process them. Hooks on the other hand are synchronous, `lightningd` cannot finish processing the event until the plugin has returned.
- Any number of plugins can subscribe to a notification topic and get notified in parallel, however only one plugin may register for `single`-mode hook types, and in all cases only one plugin may return a non-`continue` response. This avoids having multiple contradictory responses.

Hooks are considered to be an advanced feature due to the fact that `lightningd` relies on the plugin to tell it what to do next. Use them carefully, and make sure your plugins always return a valid response to any hook invocation.

As a convention, for all hooks, returning the object `{ "result" : "continue" }` results in `lightningd` behaving exactly as if no plugin is registered on the hook.

### `peer_connected`

This hook is called whenever a peer has connected and successfully completed the cryptographic handshake. The parameters have the following structure:

```json
{
  "peer": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
	"direction": "in",
    "addr": "34.239.230.56:9735",
    "features": ""
  }
}
```



The hook is sparse on information, since the plugin can use the JSON-RPC `listpeers` command to get additional details should they be required. `direction` is either `"in"` or `"out"`. The `addr` field shows the address that we are connected to ourselves, not the gossiped list of known addresses. In particular this means that the port for incoming connections is an ephemeral port, that may not be available for reconnections.

The returned result must contain a `result` member which is either the string `disconnect` or `continue`.  If `disconnect` and there's a member `error_message`, that member is sent to the peer before disconnection.

Note that `peer_connected` is a chained hook. The first plugin that decides to `disconnect` with or without an `error_message` will lead to the subsequent plugins not being called anymore.

### `recover`

This hook is called whenever the node is started using the --recovery flag. So basically whenever a user wants to recover their node with a codex32 secret, they can use --recover=<codex32secret> to use that secret as their HSM Secret.

The payload consists of the following information:
```json
{
	"codex32": "cl10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqjdsjnzedu43ns"
}
```

This hook is intended to be used for recovering the node and funds by connecting to some known peers who keep your peer storage backups with them.

### `commitment_revocation`

This hook is called whenever a channel state is updated, and the old state was revoked. State updates in Lightning consist of the following steps:

1. Proposal of a new state commitment in the form of a commitment transaction
2. Exchange of signatures for the agreed upon commitment transaction
3. Verification that the signatures match the commitment transaction
4. Exchange of revocation secrets that could be used to penalize an eventual misbehaving party

The `commitment_revocation` hook is used to inform the plugin about the state transition being completed, and deliver the penalty transaction. The penalty transaction could then be sent to a watchtower that automaticaly reacts in case one party attempts to settle using a revoked commitment.

The payload consists of the following information:

```json
{
	"commitment_txid": "58eea2cf538cfed79f4d6b809b920b40bb6b35962c4bb4cc81f5550a7728ab05",
	"penalty_tx": "02000000000101...ac00000000",
	"channel_id": "fb16398de93e8690c665873715ef590c038dfac5dd6c49a9d4b61dccfcedc2fb",
	"commitnum": 21
}
```



Notice that the `commitment_txid` could also be extracted from the sole input of the `penalty_tx`, however it is enclosed so plugins don't have to include the logic to parse transactions.

Not included are the `htlc_success` and `htlc_failure` transactions that may also be spending `commitment_tx` outputs. This is because these transactions are much more dynamic and have a predictable timeout, allowing wallets to ensure a quick checkin when the CLTV of the HTLC is about to expire.

The `commitment_revocation` hook is a chained hook, i.e., multiple plugins can register it, and they will be called in the order they were registered in. Plugins should always return `{"result": "continue"}`, otherwise subsequent hook subscribers would not get called.

### `db_write`

This hook is called whenever a change is about to be committed to the database, if you are using a SQLITE3 database (the default).
This hook will be useless (the `"writes"` field will always be empty) if you are using a PostgreSQL database.

It is currently extremely restricted:

1. a plugin registering for this hook should not perform anything that may cause a db operation in response (pretty much, anything but logging).
2. a plugin registering for this hook should not register for other hooks or commands, as these may become intermingled and break rule #1.
3. the hook will be called before your plugin is initialized!

This hook, unlike all the other hooks, is also strongly synchronous: `lightningd` will stop almost all the other processing until this hook responds.

```json
{
  "data_version": 42,
  "writes": [
    "PRAGMA foreign_keys = ON"
  ]
}
```



This hook is intended for creating continuous backups. The intent is that your backup plugin maintains three pieces of information (possibly in separate files):

1. a snapshot of the database
2. a log of database queries that will bring that snapshot up-to-date
3. the previous `data_version`

`data_version` is an unsigned 32-bit number that will always increment by 1 each time `db_write` is called. Note that this will wrap around on the limit of 32-bit numbers.

`writes` is an array of strings, each string being a database query that modifies the database.
If the `data_version` above is validated correctly, then you can simply append this to the log of database queries.

Your plugin **MUST** validate the `data_version`. It **MUST** keep track of the previous `data_version` it got, and:

1. If the new `data_version` is **_exactly_** one higher than the previous, then this is the ideal case and nothing bad happened and we should save this and continue.
2. If the new `data_version` is **_exactly_** the same value as the previous, then the previous set of queries was not committed.
   Your plugin **MAY** overwrite the previous set of queries with the current set, or it **MAY** overwrite its entire backup with a new snapshot of the database and the current `writes`
   array (treating this case as if `data_version` were two or more higher than the previous).
3. If the new `data_version` is **_less than_** the previous, your plugin **MUST** halt and catch fire, and have the operator inspect what exactly happened here.
4. Otherwise, some queries were lost and your plugin **SHOULD** recover by creating a new snapshot of the database: copy the database file, back up the given `writes` array, then delete (or atomically `rename` if in a POSIX filesystem) the previous backups of the database and SQL statements, or you **MAY** fail the hook to abort `lightningd`.

The "rolling up" of the database could be done periodically as well if the log of SQL statements has grown large.

Any response other than `{"result": "continue"}` will cause lightningd to error without
committing to the database!
This is the expected way to halt and catch fire.

`db_write` is a parallel-chained hook, i.e., multiple plugins can register it, and all of them will be invoked simultaneously without regard for order of registration.
The hook is considered handled if all registered plugins return `{"result": "continue"}`.
If any plugin returns anything else, `lightningd` will error without committing to the database.

### `invoice_payment`

This hook is called whenever a valid payment for an unpaid invoice has arrived.

```json
{
  "payment": {
    "label": "unique-label-for-invoice",
    "preimage": "0000000000000000000000000000000000000000000000000000000000000000",
    "msat": 10000
  }
}
```
Before version `23.11` the `msat` field was a string with msat-suffix, e.g: `"10000msat"`.

The hook is deliberately sparse, since the plugin can use the JSON-RPC `listinvoices` command to get additional details about this invoice. It can return a `failure_message` field as defined for final nodes in [BOLT 4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md#failure-messages), a `result` field with the string
`reject` to fail it with `incorrect_or_unknown_payment_details`, or a `result` field with the string `continue` to accept the payment.

### `openchannel`

This hook is called whenever a remote peer tries to fund a channel to us using the v1 protocol, and it has passed basic sanity checks:

```json
{
  "openchannel": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
    "funding_msat": 100000000,
    "push_msat": 0,
    "dust_limit_msat": 546000,
    "max_htlc_value_in_flight_msat": 18446744073709551615,
    "channel_reserve_msat": 1000000,
    "htlc_minimum_msat": 0,
    "feerate_per_kw": 7500,
    "to_self_delay": 5,
    "max_accepted_htlcs": 483,
    "channel_flags": 1
  }
}
```



There may be additional fields, including `shutdown_scriptpubkey` and a hex-string.  You can see the definitions of these fields in [BOLT 2's description of the open_channel message](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-open_channel-message).

The returned result must contain a `result` member which is either the string `reject` or `continue`.  If `reject` and there's a member `error_message`, that member is sent to the peer before disconnection.

For a 'continue'd result, you can also include a `close_to` address, which will be used as the output address for a mutual close transaction.

e.g.

```json
{
    "result": "continue",
    "close_to": "bc1qlq8srqnz64wgklmqvurv7qnr4rvtq2u96hhfg2",
	"mindepth": 0,
	"reserve": "1234sat"
}
```



Note that `close_to` must be a valid address for the current chain, an invalid address will cause the node to exit with an error.

- `mindepth` is the number of confirmations to require before making the channel usable. Notice that setting this to 0 (`zeroconf`) or some other low value might expose you to double-spending issues, so only lower this value from the default if you trust the peer not to
  double-spend, or you reject incoming payments, including forwards, until the funding is confirmed.

- `reserve` is an absolute value for the amount in the channel that the peer must keep on their side. This ensures that they always have something to lose, so only lower this below the 1% of funding amount if you trust the peer. The protocol requires this to be larger than the dust limit, hence it will be adjusted to be the dust limit if the specified value is below.

Note that `openchannel` is a chained hook. Therefore `close_to`, `reserve` will only be
evaluated for the first plugin that sets it. If more than one plugin tries to set a `close_to` address an error will be logged.

### `openchannel2`

This hook is called whenever a remote peer tries to fund a channel to us using the v2 protocol, and it has passed basic sanity checks:

```json
{
  "openchannel2": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
    "channel_id": "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7",
    "their_funding_msat": 100000000,
    "dust_limit_msat": 546000,
    "max_htlc_value_in_flight_msat": 18446744073709551615,
    "htlc_minimum_msat": 0,
    "funding_feerate_per_kw": 7500,
    "commitment_feerate_per_kw": 7500,
    "feerate_our_max": 10000,
    "feerate_our_min": 253,
    "to_self_delay": 5,
    "max_accepted_htlcs": 483,
    "channel_flags": 1,
    "locktime": 2453,
    "channel_max_msat": 16777215000,
    "requested_lease_msat": 100000000,
    "lease_blockheight_start": 683990,
    "node_blockheight": 683990
  }
}
```



There may be additional fields, such as `shutdown_scriptpubkey`.  You can see the definitions of these fields in [BOLT 2's description of the open_channel message](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-open_channel-message).

`requested_lease_msat`, `lease_blockheight_start`, and `node_blockheight` are
only present if the opening peer has requested a funding lease, per `option_will_fund`.

The returned result must contain a `result` member which is either the string `reject` or `continue`.  If `reject` and there's a member `error_message`, that member is sent to the peer before disconnection.

For a 'continue'd result, you can also include a `close_to` address, which will be used as the output address for a mutual close transaction; you can include a `psbt` and an `our_funding_msat` to contribute funds, inputs and outputs to this channel open.

Note that, like `openchannel_init` RPC call, the `our_funding_msat` amount must NOT be accounted for in any supplied output. Change, however, should be included and should use the `funding_feerate_per_kw` to calculate.

See `plugins/funder.c` for an example of how to use this hook to contribute funds to a channel open.

e.g.

```json
{
    "result": "continue",
    "close_to": "bc1qlq8srqnz64wgklmqvurv7qnr4rvtq2u96hhfg2",
    "psbt": "cHNidP8BADMCAAAAAQ+yBipSVZrrw28Oed52hTw3N7t0HbIyZhFdcZRH3+61AQAAAAD9////AGYAAAAAAQDfAgAAAAABARtaSZufCbC+P+/G23XVaQ8mDwZQFW1vlCsCYhLbmVrpAAAAAAD+////AvJs5ykBAAAAFgAUT6ORgb3CgFsbwSOzNLzF7jQS5s+AhB4AAAAAABepFNi369DMyAJmqX2agouvGHcDKsZkhwJHMEQCIHELIyqrqlwRjyzquEPvqiorzL2hrvdu9EBxsqppeIKiAiBykC6De/PDElnqWw49y2vTqauSJIVBgGtSc+vq5BQd+gEhAg0f8WITWvA8o4grxNKfgdrNDncqreMLeRFiteUlne+GZQAAAAEBIICEHgAAAAAAF6kU2Lfr0MzIAmapfZqCi68YdwMqxmSHAQQWABQB+tkKvNZml+JZIWRyLeSpXr7hZQz8CWxpZ2h0bmluZwEIexhVcpJl8ugM/AlsaWdodG5pbmcCAgABAA==",
    "our_funding_msat": 39999000
}
```



Note that `close_to` must be a valid address for the current chain, an invalid address will cause the node to exit with an error.

Note that `openchannel` is a chained hook. Therefore `close_to` will only be evaluated for the first plugin that sets it. If more than one plugin tries to set a `close_to` address an error will be logged.

### `openchannel2_changed`

This hook is called when we received updates to the funding transaction from the peer.

```json
{
	"openchannel2_changed": {
		"channel_id": "252d1b0a1e57895e841...",
		"psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr..."
	}
}
```



In return, we expect a `result` indicated to `continue` and an updated `psbt`.
If we have no updates to contribute, return the passed in PSBT. Once no changes to the PSBT are made on either side, the transaction construction negotiation will end and commitment transactions will be exchanged.

#### Expected Return

```json
{
	"result": "continue",
	"psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr..."
}
```



See `plugins/funder.c` for an example of how to use this hook to continue a v2 channel open.

### `openchannel2_sign`

This hook is called after we've gotten the commitment transactions for a channel open. It expects psbt to be returned which contains signatures for our inputs to the funding transaction.

```json
{
	"openchannel2_sign": {
		"channel_id": "252d1b0a1e57895e841...",
		"psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr..."
	}
}
```



In return, we expect a `result` indicated to `continue` and an partially signed `psbt`.

If we have no inputs to sign, return the passed in PSBT. Once we have also received the signatures from the peer, the funding transaction will be broadcast.

#### Expected Return

```json
{
	"result": "continue",
	"psbt": "cHNidP8BADMCAAAAAQ+yBipSVZr..."
}
```



See `plugins/funder.c` for an example of how to use this hook to sign a funding transaction.

### `rbf_channel`

Similar to `openchannel2`, the `rbf_channel` hook is called when a peer requests an RBF for a channel funding transaction.

```json
{
  "rbf_channel": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
    "channel_id": "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7",
    "their_last_funding_msat": 100000000,
    "their_funding_msat": 100000000,
    "our_last_funding_msat": 100000000,
    "funding_feerate_per_kw": 7500,
    "feerate_our_max": 10000,
    "feerate_our_min": 253,
    "channel_max_msat": 16777215000,
    "locktime": 2453,
    "requested_lease_msat": 100000000
  }
}
```



The returned result must contain a `result` member which is either the string `reject` or `continue`.  If `reject` and there's a member `error_message`, that member is sent to the peer before disconnection.

For a 'continue'd result, you can include a `psbt` and an `our_funding_msat` to contribute funds, inputs and outputs to this channel open.

Note that, like the `openchannel_init` RPC call, the `our_funding_msat` amount must NOT be accounted for in any supplied output. Change, however, should be included and should use the `funding_feerate_per_kw` to calculate.

#### Return

```json
{
    "result": "continue",
    "psbt": "cHNidP8BADMCAAAAAQ+yBipSVZrrw28Oed52hTw3N7t0HbIyZhFdcZRH3+61AQAAAAD9////AGYAAAAAAQDfAgAAAAABARtaSZufCbC+P+/G23XVaQ8mDwZQFW1vlCsCYhLbmVrpAAAAAAD+////AvJs5ykBAAAAFgAUT6ORgb3CgFsbwSOzNLzF7jQS5s+AhB4AAAAAABepFNi369DMyAJmqX2agouvGHcDKsZkhwJHMEQCIHELIyqrqlwRjyzquEPvqiorzL2hrvdu9EBxsqppeIKiAiBykC6De/PDElnqWw49y2vTqauSJIVBgGtSc+vq5BQd+gEhAg0f8WITWvA8o4grxNKfgdrNDncqreMLeRFiteUlne+GZQAAAAEBIICEHgAAAAAAF6kU2Lfr0MzIAmapfZqCi68YdwMqxmSHAQQWABQB+tkKvNZml+JZIWRyLeSpXr7hZQz8CWxpZ2h0bmluZwEIexhVcpJl8ugM/AlsaWdodG5pbmcCAgABAA==",
    "our_funding_msat": 39999000
}
```



### `htlc_accepted`

The `htlc_accepted` hook is called whenever an incoming HTLC is accepted, and its result determines how `lightningd` should treat that HTLC.

The payload of the hook call has the following format:

```json
{
  "onion": {
    "payload": "",
    "short_channel_id": "1x2x3",
    "forward_msat": 42,
    "outgoing_cltv_value": 500014,
    "shared_secret": "0000000000000000000000000000000000000000000000000000000000000000",
    "next_onion": "[1365bytes of serialized onion]"
  },
  "htlc": {
    "short_channel_id": "4x5x6",
    "id": 27,
    "amount_msat": 43,
    "cltv_expiry": 500028,
    "cltv_expiry_relative": 10,
    "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "forward_to": "0000000000000000000000000000000000000000000000000000000000000000"
}
```



For detailed information about each field please refer to [BOLT 04 of the specification](https://github.com/lightning/bolts/blob/master/04-onion-routing.md), the following is just a brief summary:

- `onion`:
  - `payload` contains the unparsed payload that was sent to us from the sender of the payment.
  - `short_channel_id` determines the channel that the sender is hinting   should be used next.  Not present if we're the final destination.
  - `forward_amount` is the amount we should be forwarding to the next hop, and should match the incoming funds in case we are the recipient.
  - `outgoing_cltv_value` determines what the CLTV value for the HTLC that we forward to the next hop should be.
  - `total_msat` specifies the total amount to pay, if present.
  - `payment_secret` specifies the payment secret (which the payer should have obtained from the invoice), if present.
  - `next_onion` is the fully processed onion that we should be sending to the next hop as part of the outgoing HTLC. Processed in this case means that we took the incoming onion, decrypted it, extracted the payload destined for us, and serialised the resulting onion again.
  - `shared_secret` is the shared secret we used to decrypt the incoming onion. It is shared with the sender that constructed the onion.
- `htlc`:
  - `short_channel_id` is the channel this payment is coming from.
  - `id` is the low-level sequential HTLC id integer as sent by the channel peer.
  - `amount` is the amount that we received with the HTLC. This amount minus the `forward_amount` is the fee that will stay with us.
  - `cltv_expiry` determines when the HTLC reverts back to the sender. `cltv_expiry` minus `outgoing_cltv_expiry` should be equal or larger than our `cltv_delta` setting.
  - `cltv_expiry_relative` hints how much time we still have to claim the HTLC. It is the `cltv_expiry` minus the current `blockheight` and is passed along mainly to avoid the plugin having to look up the current blockheight.
  - `payment_hash` is the hash whose `payment_preimage` will unlock the funds and allow us to claim the HTLC.
- `forward_to`: if set, the channel_id we intend to forward this to (will not be present if the short_channel_id was invalid or we were the final destination).

The hook response must have one of the following formats:

```json
{
  "result": "continue"
}
```



This means that the plugin does not want to do anything special and `lightningd` should continue processing it normally, i.e., resolve the payment if we're the recipient, or attempt to forward it otherwise. Notice that the usual checks such as sufficient fees and CLTV deltas are still enforced.

It can also replace the `onion.payload` by specifying a `payload` in the response.  Note that this is always a TLV-style payload, so unlike `onion.payload` there is no length prefix (and it must be at least 4 hex digits long).  This will be re-parsed; it's useful for removing onion fields which a plugin doesn't want lightningd to consider.

It can also specify `forward_to` in the response, replacing the destination.  This usually only makes sense if it wants to choose an alternate channel to the same next peer, but is useful if the `payload` is also replaced.

```json
{
  "result": "fail",
  "failure_message": "2002"
}
```



`fail` will tell `lightningd` to fail the HTLC with a given hex-encoded `failure_message` (please refer to the [spec](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) for details: `incorrect_or_unknown_payment_details` is the most common).

```json
{
  "result": "fail",
  "failure_onion": "[serialized error packet]"
}
```



Instead of `failure_message` the response can contain a hex-encoded `failure_onion` that will be used instead (please refer to the [spec](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) for details). This can be used, for example, if you're writing a bridge between two Lightning Networks. Note that `lightningd` will apply the obfuscation step to the value returned here with its own shared secret (and key type `ammag`) before returning it to the previous hop.

```json
{
  "result": "resolve",
  "payment_key": "0000000000000000000000000000000000000000000000000000000000000000"
}
```



`resolve` instructs `lightningd` to claim the HTLC by providing the preimage matching the `payment_hash` presented in the call. Notice that the plugin must ensure that the `payment_key` really matches the `payment_hash` since `lightningd` will not check and the wrong value could result in the channel being closed.

> 🚧
>
> `lightningd` will replay the HTLCs for which it doesn't have a final verdict during startup. This means that, if the plugin response wasn't processed before the HTLC was forwarded, failed, or resolved, then the plugin may see the same HTLC again during startup. It is therefore paramount that the plugin is idempotent if it talks to an external system.

The `htlc_accepted` hook is a chained hook, i.e., multiple plugins can register it, and they will be called in the order they were registered in until the first plugin return a result that is not `{"result": "continue"}`, after which the event is considered to be handled. After the event has been handled the remaining plugins will be skipped.

### `rpc_command`

The `rpc_command` hook allows a plugin to take over any RPC command. It sends the received JSON-RPC request (for any method!) to the registered plugin,

```json
{
    "rpc_command": {
        "id": 3,
        "method": "method_name",
        "params": {
            "param_1": [],
            "param_2": {},
            "param_n": "",
        }
    }
}
```



which can in turn:

Let `lightningd` execute the command with

```json
{
    "result" : "continue"
}
```



Replace the request made to `lightningd`:

```json
{
    "replace": {
        "id": 3,
        "method": "method_name",
        "params": {
            "param_1": [],
            "param_2": {},
            "param_n": "",
        }
    }
}
```



Return a custom response to the request sender:

```json
{
    "return": {
        "result": {
        }
    }
}
```



Return a custom error to the request sender:

```json
{
    "return": {
        "error": {
        }
    }
}
```



Note: The `rpc_command` hook is chainable. If two or more plugins try to replace/result/error the same `method`, only the first plugin in the chain will be respected. Others will be ignored and a warning will be logged.

### `custommsg`

The `custommsg` plugin hook is the receiving counterpart to the [`sendcustommsg`](ref:lightning-sendcustommsg) RPC method and allows plugins to handle messages that are not handled internally. The goal of these two components is to allow the implementation of custom protocols or prototypes on top of a Core Lightning node, without having to change the node's implementation itself.

The payload for a call follows this format:

```json
{
	"peer_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
	"payload": "1337ffffffff"
}
```



This payload would have been sent by the peer with the `node_id` matching `peer_id`, and the message has type `0x1337` and contents `ffffffff`. Notice that the messages are currently limited to odd-numbered types and must not match a type that is handled internally by Core Lightning. These limitations are in place in order to avoid conflicts with the internal state tracking, and avoiding disconnections or channel closures, since odd-numbered message can be
ignored by nodes (see ["it's ok to be odd" in the specification](https://github.com/lightning/bolts/blob/c74a3bbcf890799d343c62cb05fcbcdc952a1cf3/01-messaging.md#lightning-message-format) for details). The plugin must implement the parsing of the message, including the type prefix, since Core Lightning does not know how to parse the message.

Because this is a chained hook, the daemon expects the result to be `{'result': 'continue'}`. It will fail if something else is returned.

### `onion_message_recv` and `onion_message_recv_secret`

These two hooks are almost identical, in that they are called when an onion message is received.

`onion_message_recv` is used for unsolicited messages (where the source knows that it is sending to this node), and `onion_message_recv_secret` is used for messages which use a blinded path we supplied.  The latter hook will have a `pathsecret` field, the former never will.

These hooks are separate, because replies MUST be ignored unless they use the correct path (i.e. `onion_message_recv_secret`, with the expected `pathsecret`).  This avoids the source trying to probe for responses without using the designated delivery path.

The payload for a call follows this format:

```json
{
  "onion_message": {
    "pathsecret": "0000000000000000000000000000000000000000000000000000000000000000",
    "reply_blindedpath": {
      "first_node_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
      "first_scid": "100x200x300",
      "first_scid_dir": 1,
      "blinding": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
      "hops": [
        {
          "blinded_node_id": "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
          "encrypted_recipient_data": "0a020d0d"
        }
      ]
	},
    "invoice_request": "0a020d0d",
    "invoice": "0a020d0d",
    "invoice_error": "0a020d0d",
    "unknown_fields": [
      {
        "number": 12345,
        "value": "0a020d0d"
      }
    ]
  }
}
```

All fields shown here are optional: in particular, only one of "first_node_id" or the pair "first_scid" and "first_scid_dir" is present.

We suggest just returning `{"result": "continue"}`; any other result will cause the message not to be handed to any other hooks.
