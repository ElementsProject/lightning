---
title: "Event notifications"
slug: "event-notifications"
hidden: false
createdAt: "2023-02-03T08:57:15.799Z"
updatedAt: "2023-07-14T07:17:17.114Z"
---
Event notifications allow a plugin to subscribe to events in `lightningd`. `lightningd` will then send a push notification if an event matching the subscription occurred. A notification is defined in the JSON-RPC [specification][jsonrpc-spec] as an RPC call that does not include an `id` parameter:

> A Notification is a Request object without an "id" member. A Request object that is a Notification signifies the Client's lack of interest in the corresponding Response object, and as such no Response object needs to be returned to the client. The Server MUST NOT reply to a Notification, including those that are within a batch request.
>
> Notifications are not confirmable by definition, since they do not have a Response object to be returned. As such, the Client would not be aware of any errors (like e.g. "Invalid params","Internal error").

Plugins subscribe by returning an array of subscriptions as part of the `getmanifest` response. The result for the `getmanifest` call above for example subscribes to the two topics `connect` and `disconnect`. The topics that are currently defined and the corresponding payloads are listed below.

> 📘 
> 
> This is a way of specifying that you want to subscribe to all possible event notifications. It is not recommended, but is useful for plugins which want to provide generic infrastructure for others (in future, we may add the ability to dynamically subscribe/unsubscribe).

### `deprecated_oneshot`

(Added in *v24.02*)

This is a special notification, which the plugin will only receive it it set `deprecated_oneshot` to `true` in its getmanifest response.  It indicates that the immeditately following command wants a different deprecation status than the global `allow-deprecated-apis` setting.

This is possible because of the `deprecations` RPC command, where individual connections can change their deprecation settings.

```json
{
  "deprecated_oneshot": {
    "deprecated_ok": false
  }
}
```

### `channel_opened`

A notification for topic `channel_opened` is sent if a peer successfully funded a channel with us. It contains the peer id, the funding amount (in millisatoshis), the funding transaction id, and a boolean indicating if the funding transaction has been included into a block.

```json
{
  "channel_opened": {
    "id": "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
    "funding_msat": 100000000,
    "funding_txid": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
    "channel_ready": false
  }
}
```

### `channel_open_failed`

A notification to indicate that a channel open attempt has been unsuccessful.  
Useful for cleaning up state for a v2 channel open attempt. See `plugins/funder.c` for an example of how to use this.

```json
{
  "channel_open_failed": {
    "channel_id": "a2d0851832f0e30a0cf...",
  }
}
```

### `channel_state_changed`

A notification for topic `channel_state_changed` is sent every time a channel changes its state. The notification includes the `peer_id` and `channel_id`, the old and new channel states, the type of `cause` and a `message`.

```json
{
    "channel_state_changed": {
        "peer_id": "03bc9337c7a28bb784d67742ebedd30a93bacdf7e4ca16436ef3798000242b2251",
        "channel_id": "a2d0851832f0e30a0cf778a826d72f077ca86b69f72677e0267f23f63a0599b4",
        "short_channel_id" : "561820x1020x1",
        "timestamp":"2023-01-05T18:27:12.145Z",
        "old_state": "CHANNELD_NORMAL",
        "new_state": "CHANNELD_SHUTTING_DOWN",
        "cause" : "remote",
        "message" : "Peer closes channel"
    }
}
```

A `cause` can have the following values:

- "unknown"   Anything other than the reasons below. Should not happen.
- "local"     Unconscious internal reasons, e.g. dev fail of a channel.
- "user"      The operator or a plugin opened or closed a channel by intention.
- "remote"    The remote closed or funded a channel with us by intention.
- "protocol"  We need to close a channel because of bad signatures and such.
- "onchain"   A channel was closed onchain, while we were offline.

Most state changes are caused subsequentially for a prior state change, e.g. "_CLOSINGD\_COMPLETE_" is followed by "_FUNDING\_SPEND\_SEEN_". Because of this, the `cause` reflects the last known reason in terms of local or remote user interaction, protocol reasons, etc. More specifically, a `new_state` "_FUNDING\_SPEND_SEEN_" will likely _not_  have "onchain" as a `cause` but some value such as "REMOTE" or "LOCAL" depending on who initiated the closing of a channel.

Note: If the channel is not closed or being closed yet, the `cause` will reflect which side "remote" or "local" opened the channel.

Note: If the cause is "onchain" this was very likely a conscious decision of the remote peer, but we have been offline.

### `connect`

A notification for topic `connect` is sent every time a new connection to a peer is established. `direction` is either `"in"` or `"out"`.

```json
{
  "connect" :  {
    "address" : {
      "address" : "127.0.0.1",
      "port" : 38012,
      "type" : "ipv4"
  },
  "direction" : "in",
  "id" : "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59"
  }
}
```

### `disconnect`

A notification for topic `disconnect` is sent every time a connection to a peer was lost.

```json
{
  "disconnect": {
    "id": "02f6725f9c1c40333b67faea92fd211c183050f28df32cac3f9d69685fe9665432"
  }
}
```

### `custommsg`

A notification for topic `custommsg` is sent when the node receives a `custommsg`. 
```json
{
  "custommsg" : {
    "peer_id" : "02f6725f9c1c40333b67faea92fd211c183050f28df32cac3f9d69685fe9665432",
    "payload" : "1337ffffffff"
  }
}
```

This `payload` represents a `custommsg` that was send by the peer whose `node_id` matches
`peer_id`. The message has type `0x1337` and contents `ffffffff`.

To  avoid conflicts with internal state-tracking, unexpected disconnections and channel-closures
the messages are currently limited to odd-numbered messages that can be safely ignored by 
other nodes (see ["it's ok to be odd" in the specification](https://github.com/lightning/bolts/blob/c74a3bbcf890799d343c62cb05fcbcdc952a1cf3/01-messaging.md#lightning-message-format)
for details).

The plugin must implement the parsing of the message including the type prefix.

### `invoice_payment`

A notification for topic `invoice_payment` is sent every time an invoice is paid.

```json
{
  "invoice_payment": {
    "label": "unique-label-for-invoice",
    "preimage": "0000000000000000000000000000000000000000000000000000000000000000",
    "msat": 10000,
  }
}

```

Before version `23.11` the `msat` field was a string with msat-suffix, e.g: `"10000msat"`.

Note that there will be a string member "outpoint" ("txid:outnum") if
the payment was onchain (possible with the *invoices-onchain-fallback*
config option).

### `invoice_creation`

A notification for topic `invoice_creation` is sent every time an invoice is created.

```json
{
  "invoice_creation": {
    "label": "unique-label-for-invoice",
    "preimage": "0000000000000000000000000000000000000000000000000000000000000000",
    "msat": 10000
  }
}
```

Before version `23.11` the `msat` field was a string with msat-suffix, e.g: `"10000msat"`.

### `warning`

A notification for topic `warning` is sent every time a new `BROKEN`/`UNUSUAL` level(in plugins, we use `error`/`warn`) log generated, which means an unusual/borken thing happens, such as channel failed, message resolving failed...

```json
{
  "warning": {
    "level": "warn",
    "time": "1559743608.565342521",
    "source": "lightningd(17652): 0821f80652fb840239df8dc99205792bba2e559a05469915804c08420230e23c7c chan #7854:",
    "log": "Peer permanent failure in CHANNELD_NORMAL: lightning_channeld: sent ERROR bad reestablish dataloss msg"
  }
}
```

1. `level` is `warn` or `error`: `warn` means something seems bad happened  and it's under control, but we'd better check it; `error` means something extremely bad is out of control, and it may lead to crash;
2. `time` is the second since epoch;
3. `source` means where the event happened, it may have the following forms:  
   `<node_id> chan #<db_id_of_channel>:`,`lightningd(<lightningd_pid>):`,  
   `plugin-<plugin_name>:`, `<daemon_name>(<daemon_pid>):`, `jsonrpc:`,  
   `jcon fd <error_fd_to_jsonrpc>:`, `plugin-manager`;
4. `log` is the context of the original log entry.

There is also a more general version of this notification called `log`, which has the same payload. This needs to be used with caution, but it is useful for plugins that report logs remotely. For example: using OpenTelemetry.

### `forward_event`

A notification for topic `forward_event` is sent every time the status of a forward payment is set. The json format is same as the API `listforwards`.

```json
{
  "forward_event": {
    "payment_hash": "f5a6a059a25d1e329d9b094aeeec8c2191ca037d3f5b0662e21ae850debe8ea2",
    "in_channel": "103x2x1",
    "out_channel": "103x1x1",
    "in_msat": 100001001,
    "out_msat": 100000000,
    "fee_msat": 1001,
    "status": "settled",
    "received_time": 1560696342.368,
    "resolved_time": 1560696342.556
  }
}
```

or

```json
{
  "forward_event": {
    "payment_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "in_channel": "103x2x1",
    "out_channel": "110x1x0",
    "in_msat": 100001001,
    "out_msat": 100000000,
    "fee_msat": 1001,
    "status": "local_failed",
    "failcode": 16392,
    "failreason": "WIRE_PERMANENT_CHANNEL_FAILURE",
    "received_time": 1560696343.052
  }
}

```

- The status includes `offered`, `settled`, `failed` and `local_failed`, and they are all string type in json.
  - When the forward payment is valid for us, we'll set `offered` and send the forward payment to next hop to resolve;
  - When the payment forwarded by us gets paid eventually, the forward payment will change the status from `offered` to `settled`;
  - If payment fails locally(like failing to resolve locally) or the corresponding htlc with next hop fails(like htlc timeout), we will set the status as `local_failed`. `local_failed` may be set before setting `offered` or after setting `offered`. In fact, from the  
    time we receive the htlc of the previous hop, all we can know the cause of the failure is treated as `local_failed`. `local_failed` only occuors locally or happens in the htlc between us and next hop;
    - If `local_failed` is set before `offered`, this means we just received htlc from the previous hop and haven't generate htlc for next hop. In this case, the json of `forward_event` sets the fields of `out_msatoshi`, `out_msat`,`fee` and `out_channel` as 0;
      - Note: In fact, for this case we may be not sure if this incoming htlc represents a pay to us or a payment we need to forward. We just simply treat all incoming failed to resolve as `local_failed`.
    - Only in `local_failed` case, json includes `failcode` and `failreason` fields;
  - `failed` means the payment forwarded by us fails in the latter hops, and the failure isn't related to us, so we aren't accessed to the fail reason. `failed` must be set after  
    `offered`.
    - `failed` case doesn't include `failcode` and `failreason`  
      fields;
- `received_time` means when we received the htlc of this payment from the previous peer. It will be contained into all status case;
- `resolved_time` means when the htlc of this payment between us and the next peer was resolved. The resolved result may success or fail, so only `settled` and `failed` case contain `resolved_time`;
- The `failcode` and `failreason` are defined in [BOLT 4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md#failure-messages).

### `sendpay_success`

A notification for topic `sendpay_success` is sent every time a sendpay succeeds (with `complete` status). The json is the same as the return value of the commands `sendpay`/`waitsendpay` when these commands succeed.

```json
{
  "sendpay_success": {
    "id": 1,
    "payment_hash": "5c85bf402b87d4860f4a728e2e58a2418bda92cd7aea0ce494f11670cfbfb206",
    "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
    "amount_msat": 100000000,
    "amount_sent_msat": 100001001,
    "created_at": 1561390572,
    "status": "complete",
    "payment_preimage": "9540d98095fd7f37687ebb7759e733934234d4f934e34433d4998a37de3733ee"
  }
}
```

`sendpay` doesn't wait for the result of sendpay and `waitsendpay` returns the result of sendpay in specified time or timeout, but `sendpay_success` will always return the result anytime when sendpay successes if is was subscribed.

### `sendpay_failure`

A notification for topic `sendpay_failure` is sent every time a sendpay completes with `failed` status. The JSON is same as the return value of the commands `sendpay`/`waitsendpay` when these commands fail.

```json
{
  "sendpay_failure": {
    "code": 204,
    "message": "failed: WIRE_UNKNOWN_NEXT_PEER (reply from remote)",
    "data": {
      "id": 2,
      "payment_hash": "9036e3bdbd2515f1e653cb9f22f8e4c49b73aa2c36e937c926f43e33b8db8851",
      "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
      "amount_msat": 100000000,
      "amount_sent_msat": 100001001,
      "created_at": 1561395134,
      "status": "failed",
      "erring_index": 1,
      "failcode": 16394,
      "failcodename": "WIRE_UNKNOWN_NEXT_PEER",
      "erring_node": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "erring_channel": "103x2x1",
      "erring_direction": 0
    }
  }
}
```

`sendpay` doesn't wait for the result of sendpay and `waitsendpay` returns the result of sendpay in specified time or timeout, but `sendpay_failure` will always return the result anytime when sendpay fails if is was subscribed.

### `coin_movement`

A notification for topic `coin_movement` is sent to record the movement of coins.  It is only triggered by finalized ledger updates, i.e. only definitively resolved HTLCs or confirmed bitcoin transactions.

```json
{
	"coin_movement": {
		"version":2,
		"node_id":"03a7103a2322b811f7369cbb27fb213d30bbc0b012082fed3cad7e4498da2dc56b",
		"type":"chain_mvt",
		"account_id":"wallet",
		"originating_account": "wallet", // (`chain_mvt` only, optional)
		"txid":"0159693d8f3876b4def468b208712c630309381e9d106a9836fa0a9571a28722", // (`chain_mvt` only, optional)
		"utxo_txid":"0159693d8f3876b4def468b208712c630309381e9d106a9836fa0a9571a28722", // (`chain_mvt` only)
		"vout":1, // (`chain_mvt` only)
		"payment_hash": "xxx", // (either type, optional on both)
		"part_id": 0, // (`channel_mvt` only, optional)
		"credit_msat":2000000000,
		"debit_msat":0,
		"output_msat": 2000000000, // ('chain_mvt' only)
		"output_count": 2, // ('chain_mvt' only, typically only channel closes)
		"fees_msat": 382, // ('channel_mvt' only)
		"tags": ["deposit"],
		"blockheight":102, // 'chain_mvt' only
		"timestamp":1585948198,
		"coin_type":"bc"
	}
}
```

`version` indicates which version of the coin movement data struct this notification adheres to.

`node_id` specifies the node issuing the coin movement.

`type` marks the underlying mechanism which moved these coins. There are two 'types' of `coin_movements`:

- `channel_mvt`s, which occur as a result of htlcs being resolved and,
- `chain_mvt`s, which occur as a result of bitcoin txs being mined.

`account_id` is the name of this account. The node's wallet is named 'wallet', all channel funds' account are the channel id.

`originating_account` is the account that this movement originated from.  
_Only_ tagged on external events (deposits/withdrawals to an external party).

`txid` is the transaction id of the bitcoin transaction that triggered this ledger event. `utxo_txid` and `vout` identify the bitcoin output which triggered this notification. (`chain_mvt` only). Notifications tagged `journal_entry` do not have a `utxo_txid` as they're not represented in the utxo set.

`payment_hash` is the hash of the preimage used to move this payment. Only present for HTLC mediated moves (both `chain_mvt` and `channel_mvt`) A `chain_mvt` will have a `payment_hash` iff it's recording an htlc that was fulfilled onchain.

`part_id` is an identifier for parts of a multi-part payment. useful for aggregating payments for an invoice or to indicate why a payment hash appears multiple times. `channel_mvt` only

`credit` and `debit` are millisatoshi denominated amounts of the fund movement. A  
'credit' is funds deposited into an account; a `debit` is funds withdrawn.

`output_value` is the total value of the on-chain UTXO. Note that for channel opens/closes the total output value will not necessarily correspond to the amount that's credited/debited.

`output_count` is the total outputs to expect for a channel close. Useful for figuring out when every onchain output for a close has been resolved.

`fees` is an HTLC annotation for the amount of fees either paid or earned. For "invoice" tagged events, the fees are the total fees paid to send that payment. The end amount can be found by subtracting the total fees from the `debited` amount. For "routed" tagged events, both the debit/credit contain fees. Technically routed debits are the 'fee generating' event, however we include them on routed credits as well.

`tag` is a movement descriptor. Current tags are as follows:

- `deposit`: funds deposited
- `withdrawal`: funds withdrawn
- `penalty`: funds paid or gained from a penalty tx.
- `invoice`: funds paid to or received from an invoice.
- `routed`: funds routed through this node.
- `pushed`: funds pushed to peer.
- `channel_open` : channel is opened, initial channel balance
- `channel_close`: channel is closed, final channel balance
- `delayed_to_us`: on-chain output to us, spent back into our wallet
- `htlc_timeout`: on-chain htlc timeout output
- `htlc_fulfill`: on-chian htlc fulfill output
- `htlc_tx`: on-chain htlc tx has happened
- `to_wallet`: output being spent into our wallet
- `ignored`: output is being ignored
- `anchor`: an anchor output
- `to_them`: output intended to peer's wallet
- `penalized`: output we've 'lost' due to a penalty (failed cheat attempt)
- `stolen`: output we've 'lost' due to peer's cheat
- `to_miner`: output we've burned to miner (OP_RETURN)
- `opener`: tags channel_open, we are the channel opener
- `lease_fee`: amount paid as lease fee
- `leased`: tags channel_open, channel contains leased funds

`blockheight` is the block the txid is included in. `channel_mvt`s will be null, so will the blockheight for withdrawals to external parties (we issue these events when we send the tx containing them, before they're included in the chain).

The `timestamp` is seconds since Unix epoch of the node's machine time at the time lightningd broadcasts the notification.

`coin_type` is the BIP173 name for the coin which moved.

### `balance_snapshot`

Emitted after we've caught up to the chain head on first start. Lists all current accounts (`account_id` matches the `account_id` emitted from `coin_movement`). Useful for checkpointing account balances.

```json
{
    "balance_snapshot": [
	{
	    'node_id': '035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d',
	    'blockheight': 101,
	    'timestamp': 1639076327,
	    'accounts': [
		{
		    'account_id': 'wallet',
		    'balance': '0msat',
		    'coin_type': 'bcrt'
		}
	    ]
	},
	{
	    'node_id': '035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d',
	    'blockheight': 110,
	    'timestamp': 1639076343,
	    'accounts': [
		{
		    'account_id': 'wallet',
		    'balance': '995433000msat',
		    'coin_type': 'bcrt'
		}, {
		    'account_id': '5b65c199ee862f49758603a5a29081912c8816a7c0243d1667489d244d3d055f',
		     'balance': '500000000msat',
		    'coin_type': 'bcrt'
		}
	    ]
	}
    ]
}
```

### `block_added`

Emitted after each block is received from bitcoind, either during the initial sync or throughout the node's life as new blocks appear.

```json
{
 "block_added": {
   		"hash": "000000000000000000034bdb3c01652a0aa8f63d32f949313d55af2509f9d245",
      "height": 753304
    }
}
```

### `openchannel_peer_sigs`

When opening a channel with a peer using the collaborative transaction protocol `opt_dual_fund`), this notification is fired when the peer sends us their funding transaction signatures, `tx_signatures`. We update the in-progress PSBT and return it here, with the peer's signatures attached.

```json
{
  "openchannel_peer_sigs": {
    "channel_id": "252d1b0a1e5789...",
    "signed_psbt": "cHNidP8BAKgCAAAAAQ+y+61AQAAAAD9////AzbkHAAAAAAAFgAUwsyrFxwqW+natS7EG4JYYwJMVGZQwwAAAAAAACIAIKYE2s4YZ+RON6BB5lYQESHR9cA7hDm6/maYtTzSLA0hUMMAAAAAAAAiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzWYAAAAAAQDfAgAAAAABARtaSZufCbC+P+/G23XVaQ8mDwZQFW1vlCsCYhLbmVrpAAAAAAD+////AvJs5ykBAAAAFgAUT6ORgb3CgFsbwSOzNLzF7jQS5s+AhB4AAAAAABepFNi369DMyAJmqX2agouvGHcDKsZkhwJHMEQCIHELIyqrqlwRjyzquEPvqiorzL2hrvdu9EBxsqppeIKiAiBykC6De/PDElnqWw49y2vTqauSJIVBgGtSc+vq5BQd+gEhAg0f8WITWvA8o4grxNKfgdrNDncqreMLeRFiteUlne+GZQAAAAEBIICEHgAAAAAAF6kU2Lfr0MzIAmapfZqCi68YdwMqxmSHAQcXFgAUAfrZCrzWZpfiWSFkci3kqV6+4WUBCGsCRzBEAiBF31wbNWECsJ0DrPel2inWla2hYpCgaxeVgPAvFEOT2AIgWiFWN0hvUaK6kEnXhED50wQ2fBqnobsRhoy1iDDKXE0BIQPXRURck2JmXyLg2W6edm8nPzJg3qOcina/oF3SaE3czwz8CWxpZ2h0bmluZwEIexhVcpJl8ugM/AlsaWdodG5pbmcCAgABAAz8CWxpZ2h0bmluZwEIR7FutlQgkSoADPwJbGlnaHRuaW5nAQhYT+HjxFBqeAAM/AlsaWdodG5pbmcBCOpQ5iiTTNQEAA=="
  }
}
```

### `onionmessage_forward_fail`

When we receive an onion message from a peer (and it's not ratelimited), and we cannot forward it for some reason.  There are three reasons why this can be called:

1. The onion message cannot be parsed.  In this case, `outgoing` and `next_node_id`/`next_short_channel_id_dir` fields are missing.
2. The forward was by short_channel_id, but we don't know that id.  In this case, `next_node_id` is missing, but `next_short_channel_id_dir` is present.
3. The next peer wasn't connected.  In this case, only `next_short_channel_id_dir` is missing.

Example 1: Failure because next node wasn't connected:

```json
{
  "onionmessage_forward_fail": {
    "source": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
    "incoming": "0002d32df088bbe2723c619b0bb88bd0969843320f961744816cbcf30ad92d8f8db567687640ffdf492971729befd7016443514bed786fbcde7be8935f09b624868c912674abd3764099f082da36c8431a847cb486f19f4888a34ee19850b6977b2b0019b8570f9a194f952a451711a42cc9b7b26b1f0f099a43f94c2946a0e3b6425abff66f002b50ab16939d0239496309198870fbb91cf2c9e67b6092a843e827e01d44898c28d4e31d1278daef2e6d7dd4ffb7d170d102a198451c46974d93a1e86e1a752db64cd067089e42ae90be27a86dbee3462850fca616bf9aac4cfe704bcf82a4d90c9cab2f107f93c9d96a400f09fd3520d55262bd99880f82525560b4d605dfe40b87ea7a606f7a12fc86b6be45bbfb4fe10686a040523f5270a40dc125466ff2f470ee82f07cf0f55f826e669e265bba2ef4649aaeec91d3e82e02b64bd93e8d3eb3f84bc4734fe36649859d6a573a7ce32ee49ecf419892d24aa0cdf778b48bb60476c29c398b2faa2ad095b76f508e69fb1fc3b26c3495c38b5e01741557bd4f22c5e752209fd7f3bbac53bed7d43c97f59294df67ec3489ae28deafbc6a24675d0d33ec59ed698932ab39d132aea90a0c8a1577dc149769c28d1e709d37ce945e1a1a3587df288725075a55cc881a821abd8179e48183482d909371fc6132cb6eb588d1e1f99a4da625da4b1bf54365ec4426e52ea0bcc8da5b7768f0dd5cd3d16116987d24f9e99e0f1c16e7564bec502b29ff3d1dde44f438bda52d716965751e173458318dfef1bb441ae55a77cd8a3a018c21770581d65edcb50146e4c06a4a545c1629fbcbf9985ab0de8c2d7b16ce67ac97ee4475d9b890a96481bf53960350194404c84ad8ddf78c956b3d5538741dc21030f7d4407ec55a5ec41e142b3613d14955f0b19232a7e2c403aa76b5289c714697d61e2ba6ad33f9e1c68fdb0b0d3dba91170eeb2647eca097b6aed5a86a8af41c026768a03f8f0225e7f7e025152a2fd9238c54a53e95ae3c8d867b41f014ab799365f5f12c214b91b7df04ad7055930fc652b24ba4bdaa509002dee61a49b80323e5a8b576beefa50149adc9ea55d00799cdf97efb0c60c9c05e812d203034bd0c3c3405d53e22e15b9c543f7655a327ddb9879ba7959215f1562d974447ecd5ea08fbc8665619f5aee259ebf6f2dd3f851bda06861817d7751126c48beba46b63f87aacba344be60ba437b677fd6ca997848c00a79377425f2c70ea4097e29a06028bdf8d34eeda515682e148832af2ee8efa326997a7f834609363114e1015115c37c8a59b2fd18554e59a6cd049acf95ead7023d2f4654fd938f821324d6cc87161b202dfc5b69803d4b3b0f8dcd5d2eb9058973027966ea48f1b63766074fceb5827d7da4fcd50d554f0a971fdfb7760b65cf413e5653065b1b728c09f1c75aaf635a6f350a04163af02e51031642439486c623f71e78ab9141c09afcc9963808ec063bbc393163e91e21dea1d6543da8c27dcc37bd68d90fb5bff3912caf29f5c9c0398f8a4384a3bc75213cac334e0f078034fbaf0ae541fbe20da77404759c72d036750f30247cd2b9317e71dea7907047457b010acfdc17ae4671c7fcc7800031a4473f924fcc9483deaa912a838c90eae30a96355cc34303f7cd4146fcefb2cc81359adcfa60b5f5a67ee203bb21d1a6a75a7315fe25fd53b729c9e32b17eef2fda0e4e00e357a55bb4c97e82f39cf386e3c40b8a1e6aae62654ad0d050e23030061ea4baf5d3fa3395d146072e30c48ff7f7ad36199774baa8c26f0e17d26c340f294c64cdbd001929a46bd0b58d472d630bba53b848eddcec0a4e3ca098e3350c022011b2ca57719e9ba10a185e2fe0959bb4796f8806642d01700c1a5c617ae68f3ec9447a40b8751bb43b4eb1052fa0f35d",
    "path_key": "036fb5acc4ddcd66bebbc00831e856720f92255017ae200bfafaa2f5fb23aa74e2",
    "outgoing": "02010221795ac7fd20c3905ced2317c9455adcdb4166be10fd0b10b9408373c8db813c05560002da9320b96766a2b754923854bf99aa9cfe96263e24ead7d0f027b4941702fc6fdf2878caab06852f5f20857699a81c421e784a744d4d0d3706d328a8ff6c61a6d07e4f4496c6ace9b34d860c325cd0676fa7251f9fddf572fb454f0738ee3d16cb88045f325e88ba804936789539a7250584a6611a5b51d3d4c41ad4ca9d1988cdb0c32adae4261c78da204ea6123a0c3afa7c9b6891c7132fedf07f7cedfb0faa685f0fc91be657169983403a0e9d62558e0eb28456ca3f26a272cf447c2c417e34346a3a175abac1af534fa7c1d5427e2ad9343266f7edbb48f9bcb0ee4afca808572606a5a23cda7e54936ea0691e49f065b02cac3dfdb84e248ff7c69b8bd31345b295c1f58b572f72b8453bc434dc1744c8abf22d3bbda741be411fbbb7ec51fb66f229deacd56f180f92c12bd62cad53fc695aa41305b2a5751f449c361061e417a6d00a12d27d9fd0a043a40d60fd6e28f37096cb9f9f5000b088cba346a2d6d6d9db1d8f5144a625b5dd7204392f0ff4c5a2e92e8e787d336a6090c94d7f60668807429dcce5af39b8688d8cc48d1618de9b48219d3ddfa0ad4e5712966267a4bd41d8d1135e594b1d5b4de4050e46b1bc10cde4f0a401e0b14edd74b675b56f0177f713c89ec963cc97896c7aa918339104ae7eec6a16f9c08950f2d6f7f54bb8da2700e88825fead9d463b47bb9f45c11bdfeda92b5afb12942d162392ebc8e403b1c89838c772d4f6e737ff5e0eb03887a996b2f5591fec34da4eb2330e0b09b763f1165f098b204b590250f5013edbdc51fe04cd3ac9c412b0f6f7af9f88ddde58ae17e21466f3a71ab55fd557b7d52e8da8d62800313d13447ff92c557f19b52acaab60223cb7fb36ebc4b5279f097c0710fa86385e8ff4544515feb53fa0a6385f47f57e3b690e198ffc77be73ef25ef00676fdbb8750fecbc2bfdc081a0a3a2340dae8e3810f9fe7f6c365ec1903f2d4f48017b6d591e87ef148da5e41f80c02a1d4747b0e69934abf3ed57af48918b2d2facda94ce8759c2d98663e33ac1a5e293479332389d85b25cd69484d25a1e52d93cde5812bc5b69439e03339b595c4ee0035195c1a73d152a1763b7df77a48f36781c719c8c482fce687792c9fc5b2a9b51f679f82c4327b6478922ee47ee6524cb4aa63121222fa4762fa7bb6798444522030aa2c27b75cbf6f20d802e321d9b648d7f556a0d3be3e61d06a02f800c927fc15027a44d0132cf277083de6118ac163fa47d662b3274a00f0b561248e350313fbd446eb495ab9503b749ca0126b5690755ca43372db968ac7a2c41aa7f019184c3208b40e3ebd2b5d38e33cb0435b3ad2d5eec77101ae26b113c07c3044da335e57378c6cf1b2d3339d49244cb4d0f6982505ec06b85aedc91c241cfc429628fca8756b4c172f4af35e73ee57f650d0e049100d2664d016571e83ce06929ec37dc77bbd3bad59435ff2406084b24165b94704d8df16577b7100a41503a247f60f4f6a58e3fce6e789e19e5b04c64ca30e09207bb8b556db17dda1d00f7c47c391086247b63388275f2018f29d7bfd33dac7f73924f6c2e50e0d26a6f7f3ca19156e092a1f13d9205fec58d33f5e18360ab295c7798475229a95b56af4df9035e676a0bed91faa8df5b2e1131ba7d8b9155b12cb1358ae5d739893503bce95540dac5bb377660ef74bd0da5a2f655db5ecc785143cec2dba84a5208fa711cf680f027259efcfaad64e20daf8cc4ad4396296f9c8fa51e20dd457594d26fbe1f36278e5483401ad158363ea43bdae7595c434a4af3d47f25d61fee9a996bde1a018f544dfe7cb4b986c55f5d5d6783efc9078e423f7855be7415764a8b5a5fe350032f16a3b4f18db2062a5ae6446dffbb346f5429a30d9a13c7736af009ef0b9c64defca7d17bbabac9",
    "next_node_id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d"
  }
}
```

Example 2: failed because we don't know short-channel `1x2x3`:

```json
{
  "onionmessage_forward_fail": {
    "source": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
    "incoming": "0002d32df088bbe2723c619b0bb88bd0969843320f961744816cbcf30ad92d8f8db567687640ffdf492971729befd7016443514bed786fbcde7be8935f09b624868c912674abd3764099f082da36c8431a847cb486f19f4888a34ee19850b6977b2b0019b8570f9a194f952a451711a42cc9b7b26b1f0f099a43f94c2946a0e3b6425abff66f002b50ab16939d0239496309198870fbb91cf2c9e67b6092a843e827e01d44898c28d4e31d1278daef2e6d7dd4ffb7d170d102a198451c46974d93a1e86e1a752db64cd067089e42ae90be27a86dbee3462850fca616bf9aac4cfe704bcf82a4d90c9cab2f107f93c9d96a400f09fd3520d55262bd99880f82525560b4d605dfe40b87ea7a606f7a12fc86b6be45bbfb4fe10686a040523f5270a40dc125466ff2f470ee82f07cf0f55f826e669e265bba2ef4649aaeec91d3e82e02b64bd93e8d3eb3f84bc4734fe36649859d6a573a7ce32ee49ecf419892d24aa0cdf778b48bb60476c29c398b2faa2ad095b76f508e69fb1fc3b26c3495c38b5e01741557bd4f22c5e752209fd7f3bbac53bed7d43c97f59294df67ec3489ae28deafbc6a24675d0d33ec59ed698932ab39d132aea90a0c8a1577dc149769c28d1e709d37ce945e1a1a3587df288725075a55cc881a821abd8179e48183482d909371fc6132cb6eb588d1e1f99a4da625da4b1bf54365ec4426e52ea0bcc8da5b7768f0dd5cd3d16116987d24f9e99e0f1c16e7564bec502b29ff3d1dde44f438bda52d716965751e173458318dfef1bb441ae55a77cd8a3a018c21770581d65edcb50146e4c06a4a545c1629fbcbf9985ab0de8c2d7b16ce67ac97ee4475d9b890a96481bf53960350194404c84ad8ddf78c956b3d5538741dc21030f7d4407ec55a5ec41e142b3613d14955f0b19232a7e2c403aa76b5289c714697d61e2ba6ad33f9e1c68fdb0b0d3dba91170eeb2647eca097b6aed5a86a8af41c026768a03f8f0225e7f7e025152a2fd9238c54a53e95ae3c8d867b41f014ab799365f5f12c214b91b7df04ad7055930fc652b24ba4bdaa509002dee61a49b80323e5a8b576beefa50149adc9ea55d00799cdf97efb0c60c9c05e812d203034bd0c3c3405d53e22e15b9c543f7655a327ddb9879ba7959215f1562d974447ecd5ea08fbc8665619f5aee259ebf6f2dd3f851bda06861817d7751126c48beba46b63f87aacba344be60ba437b677fd6ca997848c00a79377425f2c70ea4097e29a06028bdf8d34eeda515682e148832af2ee8efa326997a7f834609363114e1015115c37c8a59b2fd18554e59a6cd049acf95ead7023d2f4654fd938f821324d6cc87161b202dfc5b69803d4b3b0f8dcd5d2eb9058973027966ea48f1b63766074fceb5827d7da4fcd50d554f0a971fdfb7760b65cf413e5653065b1b728c09f1c75aaf635a6f350a04163af02e51031642439486c623f71e78ab9141c09afcc9963808ec063bbc393163e91e21dea1d6543da8c27dcc37bd68d90fb5bff3912caf29f5c9c0398f8a4384a3bc75213cac334e0f078034fbaf0ae541fbe20da77404759c72d036750f30247cd2b9317e71dea7907047457b010acfdc17ae4671c7fcc7800031a4473f924fcc9483deaa912a838c90eae30a96355cc34303f7cd4146fcefb2cc81359adcfa60b5f5a67ee203bb21d1a6a75a7315fe25fd53b729c9e32b17eef2fda0e4e00e357a55bb4c97e82f39cf386e3c40b8a1e6aae62654ad0d050e23030061ea4baf5d3fa3395d146072e30c48ff7f7ad36199774baa8c26f0e17d26c340f294c64cdbd001929a46bd0b58d472d630bba53b848eddcec0a4e3ca098e3350c022011b2ca57719e9ba10a185e2fe0959bb4796f8806642d01700c1a5c617ae68f3ec9447a40b8751bb43b4eb1052fa0f35d",
    "path_key": "036fb5acc4ddcd66bebbc00831e856720f92255017ae200bfafaa2f5fb23aa74e2",
    "outgoing": "02010221795ac7fd20c3905ced2317c9455adcdb4166be10fd0b10b9408373c8db813c05560002da9320b96766a2b754923854bf99aa9cfe96263e24ead7d0f027b4941702fc6fdf2878caab06852f5f20857699a81c421e784a744d4d0d3706d328a8ff6c61a6d07e4f4496c6ace9b34d860c325cd0676fa7251f9fddf572fb454f0738ee3d16cb88045f325e88ba804936789539a7250584a6611a5b51d3d4c41ad4ca9d1988cdb0c32adae4261c78da204ea6123a0c3afa7c9b6891c7132fedf07f7cedfb0faa685f0fc91be657169983403a0e9d62558e0eb28456ca3f26a272cf447c2c417e34346a3a175abac1af534fa7c1d5427e2ad9343266f7edbb48f9bcb0ee4afca808572606a5a23cda7e54936ea0691e49f065b02cac3dfdb84e248ff7c69b8bd31345b295c1f58b572f72b8453bc434dc1744c8abf22d3bbda741be411fbbb7ec51fb66f229deacd56f180f92c12bd62cad53fc695aa41305b2a5751f449c361061e417a6d00a12d27d9fd0a043a40d60fd6e28f37096cb9f9f5000b088cba346a2d6d6d9db1d8f5144a625b5dd7204392f0ff4c5a2e92e8e787d336a6090c94d7f60668807429dcce5af39b8688d8cc48d1618de9b48219d3ddfa0ad4e5712966267a4bd41d8d1135e594b1d5b4de4050e46b1bc10cde4f0a401e0b14edd74b675b56f0177f713c89ec963cc97896c7aa918339104ae7eec6a16f9c08950f2d6f7f54bb8da2700e88825fead9d463b47bb9f45c11bdfeda92b5afb12942d162392ebc8e403b1c89838c772d4f6e737ff5e0eb03887a996b2f5591fec34da4eb2330e0b09b763f1165f098b204b590250f5013edbdc51fe04cd3ac9c412b0f6f7af9f88ddde58ae17e21466f3a71ab55fd557b7d52e8da8d62800313d13447ff92c557f19b52acaab60223cb7fb36ebc4b5279f097c0710fa86385e8ff4544515feb53fa0a6385f47f57e3b690e198ffc77be73ef25ef00676fdbb8750fecbc2bfdc081a0a3a2340dae8e3810f9fe7f6c365ec1903f2d4f48017b6d591e87ef148da5e41f80c02a1d4747b0e69934abf3ed57af48918b2d2facda94ce8759c2d98663e33ac1a5e293479332389d85b25cd69484d25a1e52d93cde5812bc5b69439e03339b595c4ee0035195c1a73d152a1763b7df77a48f36781c719c8c482fce687792c9fc5b2a9b51f679f82c4327b6478922ee47ee6524cb4aa63121222fa4762fa7bb6798444522030aa2c27b75cbf6f20d802e321d9b648d7f556a0d3be3e61d06a02f800c927fc15027a44d0132cf277083de6118ac163fa47d662b3274a00f0b561248e350313fbd446eb495ab9503b749ca0126b5690755ca43372db968ac7a2c41aa7f019184c3208b40e3ebd2b5d38e33cb0435b3ad2d5eec77101ae26b113c07c3044da335e57378c6cf1b2d3339d49244cb4d0f6982505ec06b85aedc91c241cfc429628fca8756b4c172f4af35e73ee57f650d0e049100d2664d016571e83ce06929ec37dc77bbd3bad59435ff2406084b24165b94704d8df16577b7100a41503a247f60f4f6a58e3fce6e789e19e5b04c64ca30e09207bb8b556db17dda1d00f7c47c391086247b63388275f2018f29d7bfd33dac7f73924f6c2e50e0d26a6f7f3ca19156e092a1f13d9205fec58d33f5e18360ab295c7798475229a95b56af4df9035e676a0bed91faa8df5b2e1131ba7d8b9155b12cb1358ae5d739893503bce95540dac5bb377660ef74bd0da5a2f655db5ecc785143cec2dba84a5208fa711cf680f027259efcfaad64e20daf8cc4ad4396296f9c8fa51e20dd457594d26fbe1f36278e5483401ad158363ea43bdae7595c434a4af3d47f25d61fee9a996bde1a018f544dfe7cb4b986c55f5d5d6783efc9078e423f7855be7415764a8b5a5fe350032f16a3b4f18db2062a5ae6446dffbb346f5429a30d9a13c7736af009ef0b9c64defca7d17bbabac9",
    "next_short_channel_id_dir": "1x2x3/1"
  }
}

```
### `shutdown`

Send in two situations: lightningd is (almost completely) shutdown, or the plugin `stop` command has been called for this plugin. In both cases the plugin has 30 seconds to exit itself, otherwise it's killed.

In the shutdown case, plugins should not interact with lightnind except via (id-less) logging or notifications. New rpc calls will fail with error code -5 and (plugin's) responses will be ignored. Because lightningd can crash or be killed, a plugin cannot rely on the shutdown notification always been send.

```json
{
    "shutdown": {
    }
}
```
