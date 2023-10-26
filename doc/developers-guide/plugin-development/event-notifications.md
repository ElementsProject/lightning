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
  "connect": {
    "id": "02f6725f9c1c40333b67faea92fd211c183050f28df32cac3f9d69685fe9665432",
    "direction": "in",
    "address": "1.2.3.4:1234"
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

### `invoice_payment`

A notification for topic `invoice_payment` is sent every time an invoice is paid.

```json
{
  "invoice_payment": {
    "label": "unique-label-for-invoice",
    "preimage": "0000000000000000000000000000000000000000000000000000000000000000",
    "amount_msat": 10000
  }
}

```

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
    "amount_msat": 10000
  }
}
```

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
- `invoice`: funds paid to or recieved from an invoice.
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

### `shutdown`

Send in two situations: lightningd is (almost completely) shutdown, or the plugin `stop` command has been called for this plugin. In both cases the plugin has 30 seconds to exit itself, otherwise it's killed.

In the shutdown case, plugins should not interact with lightnind except via (id-less) logging or notifications. New rpc calls will fail with error code -5 and (plugin's) responses will be ignored. Because lightningd can crash or be killed, a plugin cannot rely on the shutdown notification always been send.

```json
{
    "shutdown": {
    }
}
```
