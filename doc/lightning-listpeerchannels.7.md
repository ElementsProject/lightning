lightning-listpeerchannels -- Command returning data on channels of connected lightning nodes
=============================================================================================

SYNOPSIS
--------

**listpeerchannels** [*id*] 

DESCRIPTION
-----------

Command *added* in v23.02.

The **listpeerchannels** RPC command returns data on channels of the network, with the possibility to filter the channels by node id.

If no *id* is supplied, then channel data on all lightning nodes that are connected, or not connected but have open channels with this node, are returned.

- **id** (pubkey, optional): If supplied, limits the channels to just the peer with the given ID, if it exists.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listpeerchannels#1",
  "method": "listpeerchannels",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59"
  }
}
{
  "id": "example:listpeerchannels#2",
  "method": "listpeerchannels",
  "params": {
    "id": null
  }
}
```

RETURN VALUE
------------

On success, an object containing **channels** is returned. It is an array of objects, where each object contains:

- **peer\_id** (pubkey): Node Public key.
- **peer\_connected** (boolean): A boolean flag that is set to true if the peer is online.
- **state** (string) (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN", "CHANNELD\_AWAITING\_SPLICE", "DUALOPEND\_OPEN\_COMMITTED", "DUALOPEND\_OPEN\_COMMIT\_READY"): The channel state, in particular `CHANNELD_NORMAL` means the channel can be used normally.
- **opener** (string) (one of "local", "remote"): Who initiated the channel.
- **features** (array of strings):
  - (string, optional) (one of "option\_static\_remotekey", "option\_anchor\_outputs", "option\_anchors\_zero\_fee\_htlc\_tx", "option\_scid\_alias", "option\_zeroconf"): BOLT #9 features which apply to this channel.
- **reestablished** (boolean, optional): A boolean flag that is set to true if we have successfully exchanged reestablish messages with this connection. *(added v24.02)*
- **scratch\_txid** (txid, optional): The txid we would use if we went onchain now.
- **channel\_type** (object, optional): Channel\_type as negotiated with peer. *(added v23.05)*:
  - **bits** (array of u32s): Each bit set in this channel\_type.:
    - (u32, optional): Bit number.
  - **names** (array of strings): Feature name for each bit set in this channel\_type.:
    - (string, optional) (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even"): Name of feature bit.
- **updates** (object, optional): Latest gossip updates sent/received. *(added v24.02)*:
  - **local** (object): Our gossip for channel. *(added v24.02)*:
    - **htlc\_minimum\_msat** (msat): Minimum msat amount we allow. *(added v24.02)*
    - **htlc\_maximum\_msat** (msat): Maximum msat amount we allow. *(added v24.02)*
    - **cltv\_expiry\_delta** (u32): Blocks delay required between incoming and outgoing HTLCs. *(added v24.02)*
    - **fee\_base\_msat** (msat): Amount we charge to use the channel. *(added v24.02)*
    - **fee\_proportional\_millionths** (u32): Amount we charge to use the channel in parts-per-million. *(added v24.02)*
  - **remote** (object, optional): Peer's gossip for channel. *(added v24.02)*:
    - **htlc\_minimum\_msat** (msat): Minimum msat amount they allow. *(added v24.02)*
    - **htlc\_maximum\_msat** (msat): Maximum msat amount they allow. *(added v24.02)*
    - **cltv\_expiry\_delta** (u32): Blocks delay required between incoming and outgoing HTLCs. *(added v24.02)*
    - **fee\_base\_msat** (msat): Amount they charge to use the channel. *(added v24.02)*
    - **fee\_proportional\_millionths** (u32): Amount they charge to use the channel in parts-per-million. *(added v24.02)*
- **ignore\_fee\_limits** (boolean, optional): Set if we allow this peer to set fees to anything they want. *(added v23.08)*
- **lost\_state** (boolean, optional): Set if we are fallen behind i.e. lost some channel state. *(added v24.02)*
- **feerate** (object, optional): Feerates for the current tx.:
  - **perkw** (u32): Feerate per 1000 weight (i.e kSipa).
  - **perkb** (u32): Feerate per 1000 virtual bytes.
- **owner** (string, optional): The current subdaemon controlling this connection.
- **short\_channel\_id** (short\_channel\_id, optional): The short\_channel\_id (once locked in).
- **channel\_id** (hash, optional): The full channel\_id (funding txid Xored with output number).
- **funding\_txid** (txid, optional): ID of the funding transaction.
- **funding\_outnum** (u32, optional): The 0-based output number of the funding transaction which opens the channel.
- **initial\_feerate** (string, optional): For inflight opens, the first feerate used to initiate the channel open.
- **last\_feerate** (string, optional): For inflight opens, the most recent feerate used on the channel open.
- **next\_feerate** (string, optional): For inflight opens, the next feerate we'll use for the channel open.
- **next\_fee\_step** (u32, optional): For inflight opens, the next feerate step we'll use for the channel open.
- **inflight** (array of objects, optional): Current candidate funding transactions.:
  - **funding\_txid** (txid): ID of the funding transaction.
  - **funding\_outnum** (u32): The 0-based output number of the funding transaction which opens the channel.
  - **feerate** (string): The feerate for this funding transaction in per-1000-weight, with `kpw` appended.
  - **total\_funding\_msat** (msat): Total amount in the channel.
  - **splice\_amount** (integer): The amouont of sats we're splicing in or out. *(added v23.08)*
  - **our\_funding\_msat** (msat): Amount we have in the channel.
  - **scratch\_txid** (txid, optional): The commitment transaction txid we would use if we went onchain now.
- **close\_to** (hex, optional): ScriptPubkey which we have to close to if we mutual close.
- **private** (boolean, optional): If True, we will not announce this channel.
- **closer** (string, optional) (one of "local", "remote"): Who initiated the channel close (only present if closing).
- **funding** (object, optional):
  - **local\_funds\_msat** (msat): Amount of channel we funded.
  - **remote\_funds\_msat** (msat): Amount of channel they funded.
  - **pushed\_msat** (msat, optional): Amount pushed from opener to peer.
  - **fee\_paid\_msat** (msat, optional): Amount we paid peer at open.
  - **fee\_rcvd\_msat** (msat, optional): Amount we were paid by peer at open.
- **to\_us\_msat** (msat, optional): How much of channel is owed to us.
- **min\_to\_us\_msat** (msat, optional): Least amount owed to us ever. If the peer were to successfully steal from us, this is the amount we would still retain.
- **max\_to\_us\_msat** (msat, optional): Most amount owed to us ever. If we were to successfully steal from the peer, this is the amount we could potentially get.
- **total\_msat** (msat, optional): Total amount in the channel.
- **fee\_base\_msat** (msat, optional): Amount we charge to use the channel.
- **fee\_proportional\_millionths** (u32, optional): Amount we charge to use the channel in parts-per-million.
- **dust\_limit\_msat** (msat, optional): Minimum amount for an output on the channel transactions.
- **max\_total\_htlc\_in\_msat** (msat, optional): Max amount accept in a single payment.
- **their\_reserve\_msat** (msat, optional): Minimum we insist they keep in channel. If they have less than this in the channel, they cannot send to us on that channel. The default is 1% of the total channel capacity.
- **our\_reserve\_msat** (msat, optional): Minimum they insist we keep in channel. If you have less than this in the channel, you cannot send out via this channel.
- **spendable\_msat** (msat, optional): An estimate of the total we could send through channel (can be wrong because adding HTLCs requires an increase in fees paid to onchain miners, and onchain fees change dynamically according to onchain activity).
- **receivable\_msat** (msat, optional): An estimate of the total peer could send through channel.
- **minimum\_htlc\_in\_msat** (msat, optional): The minimum amount HTLC we accept.
- **minimum\_htlc\_out\_msat** (msat, optional): The minimum amount HTLC we will send.
- **maximum\_htlc\_out\_msat** (msat, optional): The maximum amount HTLC we will send.
- **their\_to\_self\_delay** (u32, optional): The number of blocks before they can take their funds if they unilateral close.
- **our\_to\_self\_delay** (u32, optional): The number of blocks before we can take our funds if we unilateral close.
- **max\_accepted\_htlcs** (u32, optional): Maximum number of incoming HTLC we will accept at once.
- **alias** (object, optional):
  - **local** (short\_channel\_id, optional): An alias assigned by this node to this channel, used for outgoing payments.
  - **remote** (short\_channel\_id, optional): An alias assigned by the remote node to this channel, usable in routehints and invoices.
- **state\_changes** (array of objects, optional): Prior state changes.:
  - **timestamp** (string): UTC timestamp of form YYYY-mm-ddTHH:MM:SS.%03dZ.
  - **old\_state** (string) (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN", "DUALOPEND\_OPEN\_COMMITTED", "DUALOPEND\_OPEN\_COMMIT\_READY", "CHANNELD\_AWAITING\_SPLICE"): Previous state.
  - **new\_state** (string) (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN", "DUALOPEND\_OPEN\_COMMITTED", "DUALOPEND\_OPEN\_COMMIT\_READY", "CHANNELD\_AWAITING\_SPLICE"): New state.
  - **cause** (string) (one of "unknown", "local", "user", "remote", "protocol", "onchain"): What caused the change.
  - **message** (string): Human-readable explanation.
- **status** (array of strings, optional):
  - (string, optional): Billboard log of significant changes.
- **in\_payments\_offered** (u64, optional): Number of incoming payment attempts.
- **in\_offered\_msat** (msat, optional): Total amount of incoming payment attempts.
- **in\_payments\_fulfilled** (u64, optional): Number of successful incoming payment attempts.
- **in\_fulfilled\_msat** (msat, optional): Total amount of successful incoming payment attempts.
- **out\_payments\_offered** (u64, optional): Number of outgoing payment attempts.
- **out\_offered\_msat** (msat, optional): Total amount of outgoing payment attempts.
- **out\_payments\_fulfilled** (u64, optional): Number of successful outgoing payment attempts.
- **out\_fulfilled\_msat** (msat, optional): Total amount of successful outgoing payment attempts.
- **last\_stable\_connection** (u64, optional): Last time we reestablished the open channel and stayed connected for 1 minute. *(added v24.02)*
- **htlcs** (array of objects, optional): Current HTLCs in this channel.:
  - **direction** (string) (one of "in", "out"): Whether it came from peer, or is going to peer. *(added v23.02)*
  - **id** (u64): Unique ID for this htlc on this channel in this direction.
  - **amount\_msat** (msat): Amount send/received for this HTLC.
  - **expiry** (u32): Block this HTLC expires at (after which an `in` direction HTLC will be returned to the peer, an `out` returned to us). If this expiry is too close, lightningd(8) will automatically unilaterally close the channel in order to enforce the timeout onchain.
  - **payment\_hash** (hash): The hash of the payment\_preimage which will prove payment.
  - **local\_trimmed** (boolean, optional) (always *true*): If this is too small to enforce onchain; it doesn't appear in the commitment transaction and will not be enforced in a unilateral close. Generally true if the HTLC (after subtracting onchain fees) is below the `dust_limit_msat` for the channel.
  - **status** (string, optional): Set if this HTLC is currently waiting on a hook (and shows what plugin).

  If **direction** is "out":
    - **state** (string) (one of "SENT\_ADD\_HTLC", "SENT\_ADD\_COMMIT", "RCVD\_ADD\_REVOCATION", "RCVD\_ADD\_ACK\_COMMIT", "SENT\_ADD\_ACK\_REVOCATION", "RCVD\_REMOVE\_HTLC", "RCVD\_REMOVE\_COMMIT", "SENT\_REMOVE\_REVOCATION", "SENT\_REMOVE\_ACK\_COMMIT", "RCVD\_REMOVE\_ACK\_REVOCATION"): Status of the HTLC.

  If **direction** is "in":
    - **state** (string) (one of "RCVD\_ADD\_HTLC", "RCVD\_ADD\_COMMIT", "SENT\_ADD\_REVOCATION", "SENT\_ADD\_ACK\_COMMIT", "RCVD\_ADD\_ACK\_REVOCATION", "SENT\_REMOVE\_HTLC", "SENT\_REMOVE\_COMMIT", "RCVD\_REMOVE\_REVOCATION", "RCVD\_REMOVE\_ACK\_COMMIT", "SENT\_REMOVE\_ACK\_REVOCATION"): Status of the HTLC.

If **peer\_connected** is *true*:
  - **reestablished** (boolean, optional): True if we have successfully exchanged reestablish messages this connection.

If **close\_to** is present:
  - **close\_to\_addr** (string, optional): The bitcoin address we will close to (present if close\_to\_addr is a standardized address).

If **scratch\_txid** is present:
  - **last\_tx\_fee\_msat** (msat): Fee attached to this the current tx.

If **short\_channel\_id** is present:
  - **direction** (u32): 0 if we're the lesser node\_id, 1 if we're the greater (as used in BOLT #7 channel\_update). *(added v23.02)*

If **inflight** is present:
  - **initial\_feerate** (string): The feerate for the initial funding transaction in per-1000-weight, with `kpw` appended.
  - **last\_feerate** (string): The feerate for the latest funding transaction in per-1000-weight, with `kpw` appended.
  - **next\_feerate** (string): The minimum feerate for the next funding transaction in per-1000-weight, with `kpw` appended.

The *state* field values (and *old\_state* / *new\_state*) are worth describing further:

  * `OPENINGD`: The channel funding protocol with the peer is ongoing and both sides are negotiating parameters.
  * `DUALOPEND_OPEN_INIT`: Like `OPENINGD`, but for v2 connections which are using collaborative opens.
  * `DUALOPEND_OPEN_COMMIT_READY`: Like `OPENINGD`, but for v2 connections which are using collaborative opens. You're ready to send your commitment signed to your peer.
  * `DUALOPEND_OPEN_COMMITTED`: Like `OPENINGD`, but for v2 connections which are using collaborative opens. You've gotten an initial signed commitment from your peer.
  * `CHANNELD_AWAITING_LOCKIN` / `DUALOPEND_AWAITING_LOCKIN`: The peer and you have agreed on channel parameters and are just waiting for the channel funding transaction to be confirmed deeply (original and collaborative open protocols, respectively). Both you and the peer must acknowledge the channel funding transaction to be confirmed deeply before entering the next state. Also, you can increase the onchain fee for channels in `DUALOPEND_AWAITING_LOCKIN` using lightning-openchannel\_bump(7).
  * `CHANNELD_NORMAL`: The channel can be used for normal payments.
  * `CHANNELD_SHUTTING_DOWN`: A mutual close was requested (by you or peer) and both of you are waiting for HTLCs in-flight to be either failed or succeeded. The channel can no longer be used for normal payments and forwarding. Mutual close will proceed only once all HTLCs in the channel have either been fulfilled or failed.
  * `CLOSINGD_SIGEXCHANGE`: You and the peer are negotiating the mutual close onchain fee.
  * `CLOSINGD_COMPLETE`: You and the peer have agreed on the mutual close onchain fee and are awaiting the mutual close getting confirmed deeply.
  * `AWAITING_UNILATERAL`: You initiated a unilateral close, and are now waiting for the peer-selected unilateral close timeout to complete.
  * `FUNDING_SPEND_SEEN`: You saw the funding transaction getting spent (usually the peer initiated a unilateral close) and will now determine what exactly happened (i.e. if it was a theft attempt).
  * `ONCHAIN`: You saw the funding transaction getting spent and now know what happened (i.e. if it was a proper unilateral close by the peer, or a theft attempt).

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "channels": [
    {
      "peer_id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "peer_connected": true,
      "channel_type": {
        "bits": [
          12
        ],
        "names": [
          "static_remotekey/even"
        ]
      },
      "updates": {
        "local": {
          "htlc_minimum_msat": 0,
          "htlc_maximum_msat": 990000000,
          "cltv_expiry_delta": 6,
          "fee_base_msat": 1,
          "fee_proportional_millionths": 10
        }
      },
      "state": "CHANNELD_AWAITING_LOCKIN",
      "scratch_txid": "4e9c2866b9ae1f765b89ea7ec37428c900ea97f717f85f00e3db852cb6aea3a8",
      "last_tx_fee_msat": 5430000,
      "feerate": {
        "perkw": 7500,
        "perkb": 30000
      },
      "owner": "channeld",
      "direction": 1,
      "channel_id": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "funding_txid": "6c0a3d8f32f556f3bd8b8c85413c4636a9513c6195abb925ea73c47183d40b7b",
      "funding_outnum": 0,
      "close_to_addr": "bcrt1pamt5tqzd49uyessr7437l2vllf20muqmzdauje8x8scjgpc0l0nqhyqcyp",
      "close_to": "5120eed745804da9784cc203f563efa99ffa54fdf01b137bc964e63c3124070ffbe6",
      "private": false,
      "opener": "local",
      "alias": {
        "local": "5589251x14022525x17398"
      },
      "features": [
        "option_static_remotekey"
      ],
      "funding": {
        "local_funds_msat": 1000000000,
        "remote_funds_msat": 0,
        "pushed_msat": 0
      },
      "to_us_msat": 1000000000,
      "min_to_us_msat": 1000000000,
      "max_to_us_msat": 1000000000,
      "total_msat": 1000000000,
      "fee_base_msat": 1,
      "fee_proportional_millionths": 10,
      "dust_limit_msat": 546000,
      "max_total_htlc_in_msat": 18446744073709552000,
      "their_reserve_msat": 10000000,
      "our_reserve_msat": 10000000,
      "spendable_msat": 973980000,
      "receivable_msat": 0,
      "minimum_htlc_in_msat": 0,
      "minimum_htlc_out_msat": 0,
      "maximum_htlc_out_msat": 990000000,
      "their_to_self_delay": 5,
      "our_to_self_delay": 5,
      "max_accepted_htlcs": 483,
      "state_changes": [],
      "status": [],
      "in_payments_offered": 0,
      "in_offered_msat": 0,
      "in_payments_fulfilled": 0,
      "in_fulfilled_msat": 0,
      "out_payments_offered": 0,
      "out_offered_msat": 0,
      "out_payments_fulfilled": 0,
      "out_fulfilled_msat": 0,
      "htlcs": []
    }
  ]
}
{
  "channels": [
    {
      "peer_id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "peer_connected": true,
      "reestablished": true,
      "channel_type": {
        "bits": [
          12,
          22
        ],
        "names": [
          "static_remotekey/even",
          "anchors_zero_fee_htlc_tx/even"
        ]
      },
      "updates": {
        "local": {
          "htlc_minimum_msat": 0,
          "htlc_maximum_msat": 990000000,
          "cltv_expiry_delta": 6,
          "fee_base_msat": 1,
          "fee_proportional_millionths": 10
        },
        "remote": {
          "htlc_minimum_msat": 0,
          "htlc_maximum_msat": 990000000,
          "cltv_expiry_delta": 6,
          "fee_base_msat": 1,
          "fee_proportional_millionths": 10
        }
      },
      "state": "CHANNELD_NORMAL",
      "scratch_txid": "ece66657d6203a4ea77807f566fd5b98a78b659f0cd59ce9200aa3bd6875ee25",
      "last_tx_fee_msat": 4545000,
      "lost_state": false,
      "feerate": {
        "perkw": 3750,
        "perkb": 15000
      },
      "owner": "channeld",
      "short_channel_id": "103x1x0",
      "direction": 1,
      "channel_id": "def5ef03e0d36ed65de814c0a8d6599a502fe1afb8e956529320bb350e876b5f",
      "funding_txid": "5f6b870e35bb20935256e9b8afe12f509a59d6a8c014e85dd66ed3e003eff5de",
      "funding_outnum": 0,
      "close_to_addr": "bcrt1pamt5tqzd49uyessr7437l2vllf20muqmzdauje8x8scjgpc0l0nqhyqcyp",
      "close_to": "5120eed745804da9784cc203f563efa99ffa54fdf01b137bc964e63c3124070ffbe6",
      "private": false,
      "opener": "local",
      "alias": {
        "local": "15447035x5589520x8959",
        "remote": "6036590x13481428x5501"
      },
      "features": [
        "option_static_remotekey",
        "option_anchors_zero_fee_htlc_tx"
      ],
      "funding": {
        "local_funds_msat": 1000000000,
        "remote_funds_msat": 0,
        "pushed_msat": 0
      },
      "to_us_msat": 1000000000,
      "min_to_us_msat": 1000000000,
      "max_to_us_msat": 1000000000,
      "total_msat": 1000000000,
      "fee_base_msat": 1,
      "fee_proportional_millionths": 10,
      "dust_limit_msat": 546000,
      "max_total_htlc_in_msat": 18446744073709552000,
      "their_reserve_msat": 10000000,
      "our_reserve_msat": 10000000,
      "spendable_msat": 978330000,
      "receivable_msat": 0,
      "minimum_htlc_in_msat": 0,
      "minimum_htlc_out_msat": 0,
      "maximum_htlc_out_msat": 990000000,
      "their_to_self_delay": 5,
      "our_to_self_delay": 5,
      "max_accepted_htlcs": 483,
      "state_changes": [
        {
          "timestamp": "2024-02-22T17:48:57.127Z",
          "old_state": "CHANNELD_AWAITING_LOCKIN",
          "new_state": "CHANNELD_NORMAL",
          "cause": "user",
          "message": "Lockin complete"
        }
      ],
      "status": [
        "CHANNELD_NORMAL:Channel ready for use."
      ],
      "in_payments_offered": 0,
      "in_offered_msat": 0,
      "in_payments_fulfilled": 0,
      "in_fulfilled_msat": 0,
      "out_payments_offered": 0,
      "out_offered_msat": 0,
      "out_payments_fulfilled": 0,
      "out_fulfilled_msat": 0,
      "htlcs": []
    }
  ]
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.

AUTHOR
------

Michael Hawkins <<michael.hawkins@protonmail.com>>.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel\_start(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
Lightning RFC site (BOLT #9): 
<https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md>
