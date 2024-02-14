lightning-listpeers -- Command returning data on connected lightning nodes
==========================================================================

SYNOPSIS
--------

**listpeers** [*id*] [*level*] 

DESCRIPTION
-----------

The **listpeers** RPC command returns data on nodes that are connected or are not connected but have open channels with this node.

Once a connection to another lightning node has been established, using the **connect** command, data on the node can be returned using **listpeers** and the *id* that was used with the **connect** command.

If no *id* is supplied, then data on all lightning nodes that are connected, or not connected but have open channels with this node, are returned.

If a channel is open with a node and the connection has been lost, then the node will still appear in the output of the command and the value of the *connected* attribute of the node will be "false".

The channel will remain open for a set blocktime, after which if the connection has not been re-established, the channel will close and the node will no longer appear in the command output.

- **id** (pubkey, optional): If supplied, limits the result to just the peer with the given ID, if it exists.
- **level** (string, optional) (one of "io", "debug", "info", "unusual"): Supplying level will show log entries related to that peer at the given log level.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listpeers#1",
  "method": "listpeers",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    "level": null
  }
}
{
  "id": "example:listpeers#2",
  "method": "listpeers",
  "params": {
    "id": null,
    "level": null
  }
}
```

RETURN VALUE
------------

On success, an object containing **peers** is returned. It is an array of objects, where each object contains:

- **id** (pubkey): The unique id of the peer.
- **connected** (boolean): Value showing the connection status.
- **num\_channels** (u32): The number of channels the peer has with this node. *(added v23.02)*
- **log** (array of objects, optional): If *level* is specified, logs for this peer.:
  - **type** (string) (one of "SKIPPED", "BROKEN", "UNUSUAL", "INFO", "DEBUG", "IO\_IN", "IO\_OUT")

  If **type** is "SKIPPED":
    - **num\_skipped** (u32): Number of deleted/omitted entries.

  If **type** is "BROKEN", "UNUSUAL", "INFO" or "DEBUG":
    - **time** (string): UNIX timestamp with 9 decimal places.
    - **source** (string): The particular logbook this was found in.
    - **log** (string): The actual log message.
    - **node\_id** (pubkey): The peer this is associated with.

  If **type** is "IO\_IN" or "IO\_OUT":
    - **time** (string): UNIX timestamp with 9 decimal places.
    - **source** (string): The particular logbook this was found in.
    - **log** (string): The actual log message.
    - **node\_id** (pubkey): The peer this is associated with.
    - **data** (hex): The IO which occurred.
- **channels** (array of objects, optional): Channels with this peer. **deprecated in v23.02, removed after v24.02**:
  - **state** (string) (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN", "DUALOPEND\_OPEN\_COMMITTED", "DUALOPEND\_OPEN\_COMMIT\_READY"): Current state of the channel:
   * `OPENINGD`: The channel funding protocol with the peer is ongoing and both sides are negotiating parameters.
   * `CHANNELD_AWAITING_LOCKIN`: The peer and you have agreed on channel parameters and are just waiting for the channel funding transaction to be confirmed deeply. Both you and the peer must acknowledge the channel funding transaction to be confirmed deeply before entering the next state.
   * `CHANNELD_NORMAL`: The channel can be used for normal payments.
   * `CHANNELD_SHUTTING_DOWN`: A mutual close was requested (by you or peer) and both of you are waiting for HTLCs in-flight to be either failed or succeeded. The channel can no longer be used for normal payments and forwarding. Mutual close will proceed only once all HTLCs in the channel have either been fulfilled or failed.
   * `CLOSINGD_SIGEXCHANGE`: You and the peer are negotiating the mutual close onchain fee.
   * `CLOSINGD_COMPLETE`: You and the peer have agreed on the mutual close onchain fee and are awaiting the mutual close getting confirmed deeply.
   * `AWAITING_UNILATERAL`: You initiated a unilateral close, and are now waiting for the peer-selected unilateral close timeout to complete.
   * `FUNDING_SPEND_SEEN`: You saw the funding transaction getting spent (usually the peer initiated a unilateral close) and will now determine what exactly happened (i.e. if it was a theft attempt).
   * `ONCHAIN`: You saw the funding transaction getting spent and now know what happened (i.e. if it was a proper unilateral close by the peer, or a theft attempt).
   * `CLOSED`: The channel closure has been confirmed deeply. The channel will eventually be removed from this array.
  - **opener** (string) (one of "local", "remote"): Who initiated the channel.
  - **features** (array of strings):
    - (string, optional) (one of "option\_static\_remotekey", "option\_anchor\_outputs", "option\_scid\_alias", "option\_zeroconf"): BOLT #9 features which apply to this channel.
  - **scratch\_txid** (txid, optional): The txid we would use if we went onchain now.
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
    - **our\_funding\_msat** (msat): Amount we have in the channel.
    - **splice\_amount** (integer): The amouont of sats we're splicing in or out. *(added v23.08)*
    - **scratch\_txid** (txid): The commitment transaction txid we would use if we went onchain now.
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
    - **old\_state** (string) (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN", "DUALOPEND\_OPEN\_COMMITTED", "DUALOPEND\_OPEN\_COMMIT\_READY"): Previous state.
    - **new\_state** (string) (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN", "DUALOPEND\_OPEN\_COMMITTED", "DUALOPEND\_OPEN\_COMMIT\_READY"): New state.
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
  - **htlcs** (array of objects, optional): Current HTLCs in this channel.:
    - **direction** (string) (one of "in", "out"): Whether it came from peer, or is going to peer.
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

  If **close\_to** is present:
    - **close\_to\_addr** (string, optional): The bitcoin address we will close to (present if close\_to\_addr is a standardized address).

  If **scratch\_txid** is present:
    - **last\_tx\_fee\_msat** (msat): Fee attached to this the current tx.

  If **short\_channel\_id** is present:
    - **direction** (u32): 0 if we're the lesser node\_id, 1 if we're the greater (as used in BOLT #7 channel\_update).

  If **inflight** is present:
    - **initial\_feerate** (string): The feerate for the initial funding transaction in per-1000-weight, with `kpw` appended.
    - **last\_feerate** (string): The feerate for the latest funding transaction in per-1000-weight, with `kpw` appended.
    - **next\_feerate** (string): The minimum feerate for the next funding transaction in per-1000-weight, with `kpw` appended.

If **connected** is *true*:
  - **netaddr** (array of strings): A single entry array.:
    - (string, optional): Address, e.g. 1.2.3.4:1234.
  - **features** (hex): Bitmap of BOLT #9 features from peer's INIT message.
  - **remote\_addr** (string, optional): The public IPv4/6 address the peer sees us from, e.g. 1.2.3.4:1234.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "peers": [
    {
      "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "connected": true,
      "num_channels": 1,
      "netaddr": [
        "127.0.0.1:44619"
      ],
      "features": "08a0000a0a69a2"
    }
  ]
}
{
  "peers": [
    {
      "id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
      "connected": true,
      "num_channels": 1,
      "netaddr": [
        "127.0.0.1:48862"
      ],
      "features": "08a0000a0a69a2"
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

lightning-connect(7), lightning-fundchannel\_start(7), lightning-setchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
Lightning RFC site (BOLT #9):
<https://github.com/lightning/bolts/blob/master/09-features.md>
