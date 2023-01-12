lightning-listpeerchannels -- Command returning data on channels of connected lightning nodes
==========================================================================

SYNOPSIS
--------

**listpeerchannels** \[*id*\]

DESCRIPTION
-----------

The **listpeerchannels** RPC command returns data on channels of the network, with the possibility to filter the channels by node id.

If no *id* is supplied, then channel data on all lightning nodes that are
connected, or not connected but have open channels with this node, are
returned.

Supplying *id* will filter the results to only return channel data that match *id*,
if one exists.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **channels** is returned.  It is an array of objects, where each object contains:

- **peer\_id** (pubkey): Node Public key
- **peer\_connected** (boolean): A boolean flag that is set to true if the peer is online
- **state** (string): the channel state, in particular "CHANNELD\_NORMAL" means the channel can be used normally (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN")
- **opener** (string): Who initiated the channel (one of "local", "remote")
- **features** (array of strings):
  - BOLT #9 features which apply to this channel (one of "option\_static\_remotekey", "option\_anchor\_outputs", "option\_zeroconf")
- **scratch\_txid** (txid, optional): The txid we would use if we went onchain now
- **feerate** (object, optional): Feerates for the current tx:
  - **perkw** (u32): Feerate per 1000 weight (i.e kSipa)
  - **perkb** (u32): Feerate per 1000 virtual bytes
- **owner** (string, optional): The current subdaemon controlling this connection
- **short\_channel\_id** (short\_channel\_id, optional): The short\_channel\_id (once locked in)
- **channel\_id** (hash, optional): The full channel\_id (always 64 characters)
- **funding\_txid** (txid, optional): ID of the funding transaction
- **funding\_outnum** (u32, optional): The 0-based output number of the funding transaction which opens the channel
- **initial\_feerate** (string, optional): For inflight opens, the first feerate used to initiate the channel open
- **last\_feerate** (string, optional): For inflight opens, the most recent feerate used on the channel open
- **next\_feerate** (string, optional): For inflight opens, the next feerate we'll use for the channel open
- **next\_fee\_step** (u32, optional): For inflight opens, the next feerate step we'll use for the channel open
- **inflight** (array of objects, optional): Current candidate funding transactions (only for dual-funding):
  - **funding\_txid** (txid): ID of the funding transaction
  - **funding\_outnum** (u32): The 0-based output number of the funding transaction which opens the channel
  - **feerate** (string): The feerate for this funding transaction in per-1000-weight, with "kpw" appended
  - **total\_funding\_msat** (msat): total amount in the channel
  - **our\_funding\_msat** (msat): amount we have in the channel
  - **scratch\_txid** (txid): The commitment transaction txid we would use if we went onchain now
- **close\_to** (hex, optional): scriptPubkey which we have to close to if we mutual close
- **private** (boolean, optional): if False, we will not announce this channel
- **closer** (string, optional): Who initiated the channel close (one of "local", "remote")
- **funding** (object, optional):
  - **local\_funds\_msat** (msat): Amount of channel we funded
  - **remote\_funds\_msat** (msat): Amount of channel they funded
  - **local\_msat** (msat, optional): Amount of channel we funded (deprecated)
  - **remote\_msat** (msat, optional): Amount of channel they funded (deprecated)
  - **pushed\_msat** (msat, optional): Amount pushed from opener to peer
  - **fee\_paid\_msat** (msat, optional): Amount we paid peer at open
  - **fee\_rcvd\_msat** (msat, optional): Amount we were paid by peer at open
- **to\_us\_msat** (msat, optional): how much of channel is owed to us
- **min\_to\_us\_msat** (msat, optional): least amount owed to us ever
- **max\_to\_us\_msat** (msat, optional): most amount owed to us ever
- **total\_msat** (msat, optional): total amount in the channel
- **fee\_base\_msat** (msat, optional): amount we charge to use the channel
- **fee\_proportional\_millionths** (u32, optional): amount we charge to use the channel in parts-per-million
- **dust\_limit\_msat** (msat, optional): minimum amount for an output on the channel transactions
- **max\_total\_htlc\_in\_msat** (msat, optional): max amount accept in a single payment
- **their\_reserve\_msat** (msat, optional): minimum we insist they keep in channel
- **our\_reserve\_msat** (msat, optional): minimum they insist we keep in channel
- **spendable\_msat** (msat, optional): total we could send through channel
- **receivable\_msat** (msat, optional): total peer could send through channel
- **minimum\_htlc\_in\_msat** (msat, optional): the minimum amount HTLC we accept
- **minimum\_htlc\_out\_msat** (msat, optional): the minimum amount HTLC we will send
- **maximum\_htlc\_out\_msat** (msat, optional): the maximum amount HTLC we will send
- **their\_to\_self\_delay** (u32, optional): the number of blocks before they can take their funds if they unilateral close
- **our\_to\_self\_delay** (u32, optional): the number of blocks before we can take our funds if we unilateral close
- **max\_accepted\_htlcs** (u32, optional): Maximum number of incoming HTLC we will accept at once
- **alias** (object, optional):
  - **local** (short\_channel\_id, optional): An alias assigned by this node to this channel, used for outgoing payments
  - **remote** (short\_channel\_id, optional): An alias assigned by the remote node to this channel, usable in routehints and invoices
- **state\_changes** (array of objects, optional): Prior state changes:
  - **timestamp** (string): UTC timestamp of form YYYY-mm-ddTHH:MM:SS.%03dZ
  - **old\_state** (string): Previous state (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN")
  - **new\_state** (string): New state (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN")
  - **cause** (string): What caused the change (one of "unknown", "local", "user", "remote", "protocol", "onchain")
  - **message** (string): Human-readable explanation
- **status** (array of strings, optional):
  - Billboard log of significant changes
- **in\_payments\_offered** (u64, optional): Number of incoming payment attempts
- **in\_offered\_msat** (msat, optional): Total amount of incoming payment attempts
- **in\_payments\_fulfilled** (u64, optional): Number of successful incoming payment attempts
- **in\_fulfilled\_msat** (msat, optional): Total amount of successful incoming payment attempts
- **out\_payments\_offered** (u64, optional): Number of outgoing payment attempts
- **out\_offered\_msat** (msat, optional): Total amount of outgoing payment attempts
- **out\_payments\_fulfilled** (u64, optional): Number of successful outgoing payment attempts
- **out\_fulfilled\_msat** (msat, optional): Total amount of successful outgoing payment attempts
- **htlcs** (array of objects, optional): current HTLCs in this channel:
  - **direction** (string): Whether it came from peer, or is going to peer (one of "in", "out")
  - **id** (u64): Unique ID for this htlc on this channel in this direction
  - **amount\_msat** (msat): Amount send/received for this HTLC
  - **expiry** (u32): Block this HTLC expires at
  - **payment\_hash** (hash): the hash of the payment\_preimage which will prove payment (always 64 characters)
  - **local\_trimmed** (boolean, optional): if this is too small to enforce onchain (always *true*)
  - **status** (string, optional): set if this HTLC is currently waiting on a hook (and shows what plugin)

  If **direction** is "out":

    - **state** (string): Status of the HTLC (one of "SENT\_ADD\_HTLC", "SENT\_ADD\_COMMIT", "RCVD\_ADD\_REVOCATION", "RCVD\_ADD\_ACK\_COMMIT", "SENT\_ADD\_ACK\_REVOCATION", "RCVD\_REMOVE\_HTLC", "RCVD\_REMOVE\_COMMIT", "SENT\_REMOVE\_REVOCATION", "SENT\_REMOVE\_ACK\_COMMIT", "RCVD\_REMOVE\_ACK\_REVOCATION")

  If **direction** is "in":

    - **state** (string): Status of the HTLC (one of "RCVD\_ADD\_HTLC", "RCVD\_ADD\_COMMIT", "SENT\_ADD\_REVOCATION", "SENT\_ADD\_ACK\_COMMIT", "RCVD\_ADD\_ACK\_REVOCATION", "SENT\_REMOVE\_HTLC", "SENT\_REMOVE\_COMMIT", "RCVD\_REMOVE\_REVOCATION", "RCVD\_REMOVE\_ACK\_COMMIT", "SENT\_REMOVE\_ACK\_REVOCATION")

If **close\_to** is present:

  - **close\_to\_addr** (string, optional): The bitcoin address we will close to

If **scratch\_txid** is present:

  - **last\_tx\_fee\_msat** (msat): fee attached to this the current tx

If **short\_channel\_id** is present:

  - **direction** (u32): 0 if we're the lesser node\_id, 1 if we're the greater

If **inflight** is present:

  - **initial\_feerate** (string): The feerate for the initial funding transaction in per-1000-weight, with "kpw" appended
  - **last\_feerate** (string): The feerate for the latest funding transaction in per-1000-weight, with "kpw" appended
  - **next\_feerate** (string): The minimum feerate for the next funding transaction in per-1000-weight, with "kpw" appended

[comment]: # (GENERATE-FROM-SCHEMA-END)

On success, an object with a "channels" key is returned containing a list
of 0 or more objects. If *id* and/or *status* are supplied and no matching
nodes are found, a "channels" object with an empty list is returned.

The objects in the *channels* array will have at least these fields:

* *state*: Any of these strings:
  * `"OPENINGD"`: The channel funding protocol with the peer is ongoing
    and both sides are negotiating parameters.
  * `"CHANNELD_AWAITING_LOCKIN"`: The peer and you have agreed on channel
    parameters and are just waiting for the channel funding transaction to
    be confirmed deeply.
    Both you and the peer must acknowledge the channel funding transaction
    to be confirmed deeply before entering the next state.
  * `"CHANNELD_NORMAL"`: The channel can be used for normal payments.
  * `"CHANNELD_SHUTTING_DOWN"`: A mutual close was requested (by you or
    peer) and both of you are waiting for HTLCs in-flight to be either
    failed or succeeded.
    The channel can no longer be used for normal payments and forwarding.
    Mutual close will proceed only once all HTLCs in the channel have
    either been fulfilled or failed.
  * `"CLOSINGD_SIGEXCHANGE"`: You and the peer are negotiating the mutual
    close onchain fee.
  * `"CLOSINGD_COMPLETE"`: You and the peer have agreed on the mutual close
    onchain fee and are awaiting the mutual close getting confirmed deeply.
  * `"AWAITING_UNILATERAL"`: You initiated a unilateral close, and are now
    waiting for the peer-selected unilateral close timeout to complete.
  * `"FUNDING_SPEND_SEEN"`: You saw the funding transaction getting
    spent (usually the peer initiated a unilateral close) and will now
    determine what exactly happened (i.e. if it was a theft attempt).
  * `"ONCHAIN"`: You saw the funding transaction getting spent and now
    know what happened (i.e. if it was a proper unilateral close by the
    peer, or a theft attempt).
  * `"CLOSED"`: The channel closure has been confirmed deeply.
    The channel will eventually be removed from this array.
* *state\_changes*: An array of objects describing prior state change events.
* *opener*: A string `"local"` or `"remote`" describing which side opened this
  channel.
* *closer*: A string `"local"` or `"remote`" describing which side
  closed this channel or `null` if the channel is not (being) closed yet.
* *status*: An array of strings containing the most important log messages
  relevant to this channel.
  Also known as the "billboard".
* *owner*: A string describing which particular sub-daemon of `lightningd`
  currently is responsible for this channel.
  One of: `"lightning_openingd"`, `"lightning_channeld"`,
  `"lightning_closingd"`, `"lightning_onchaind"`.
* *to\_us\_msat*: A string describing how much of the funds is owned by us;
  a number followed by a string unit.
* *total\_msat*: A string describing the total capacity of the channel;
  a number followed by a string unit.
* *fee\_base\_msat*: The fixed routing fee we charge for forwards going out over
  this channel, regardless of payment size.
* *fee\_proportional\_millionths*: The proportional routing fees in ppm (parts-
  per-millionths) we charge for forwards going out over this channel.
* *features*: An array of feature names supported by this channel.

These fields may exist if the channel has gotten beyond the `"OPENINGD"`
state, or in various circumstances:

* *short\_channel\_id*: A string of the short channel ID for the channel;
  Format is `"BBBBxTTTxOOO"`, where `"BBBB"` is the numeric block height
  at which the funding transaction was confirmed, `"TTT"` is the numeric
  funding transaction index within that block, and `"OOO"` is the
  numeric output index of the transaction output that actually anchors
  this channel.
* *direction*: The channel-direction we own, as per  BOLT \#7.
  We own channel-direction 0 if our node ID is "less than" the peer node ID
  in a lexicographical ordering of our node IDs, otherwise we own
  channel-direction 1.
  Our `channel_update` will use this *direction*.
* *channel\_id*: The full channel ID of the channel;
  the funding transaction ID XORed with the output number.
* *funding\_txid*: The funding transaction ID of the channel.
* *close\_to*: The raw `scriptPubKey` that was indicated in the starting
  **fundchannel\_start** command and accepted by the peer.
  If the `scriptPubKey` encodes a standardized address, an additional
  *close\_to\_addr* field will be present with the standardized address.
* *private*: A boolean, true if the channel is unpublished, false if the
  channel is published.
* *funding\_msat*: An object, whose field names are the node
  IDs involved in the channel, and whose values are strings (numbers with
  a unit suffix) indicating how much that node originally contributed in
  opening the channel.
* *min\_to\_us\_msat*: A string describing the historic point at which
  we owned the least amount of funds in this channel;
  a number followed by a string unit.
  If the peer were to succesfully steal from us, this is the amount we
  would still retain.
* *max\_to\_us\_msat*: A string describing the historic point at which
  we owned the most amount of funds in this channel;
  a number followed by a string unit.
  If we were to successfully steal from the peer, this is the amount we
  could potentially get.
* *dust\_limit\_msat*: A string describing an amount;
  if an HTLC or the amount wholly-owned by one node is at or below this
  amount, it will be considered "dusty" and will not appear in a close
  transaction, and will be donated to miners as fee;
  a number followed by a string unit.
* *max\_total\_htlc\_in\_msat*: A string describing an amount;
  the sum of all HTLCs in the channel cannot exceed this amount;
  a number followed by a string unit.
* *their\_reserve\_msat*: A string describing the minimum amount that
  the peer must keep in the channel when it attempts to send out;
  if it has less than this in the channel, it cannot send to us on
  that channel;
  a number followed by a string unit.
  We impose this on them, default is 1% of the total channel capacity.
* *our\_reserve\_msat*: A string describing the minimum amount that
  you must keep in the channel when you attempt to send out;
  if you have less than this in the channel, you cannot send out
  via this channel;
  a number followed by a string unit.
  The peer imposes this on us, default is 1% of the total channel capacity.
* *spendable\_msat* and *receivable\_msat*: A string describing an
  ***estimate*** of how much we can send or receive over this channel in a
  single payment (or payment-part for multi-part payments);
  a number followed by a string unit.
  This is an ***estimate***, which can be wrong because adding HTLCs requires
  an increase in fees paid to onchain miners, and onchain fees change
  dynamically according to onchain activity.
  For a sufficiently-large channel, this can be limited by the rules imposed
  under certain blockchains;
  for example, individual Bitcoin mainnet payment-parts cannot exceed
  42.94967295 mBTC.
* *minimum\_htlc\_in\_msat*: A string describing the minimum amount that
  an HTLC must have before we accept it.
* *their\_to\_self\_delay*: The number of blocks that the peer must wait
  to claim their funds, if they close unilaterally.
* *our\_to\_self\_delay*: The number of blocks that you must wait to claim
  your funds, if you close unilaterally.
* *max\_accepted\_htlcs*: The maximum number of HTLCs you will accept on
  this channel.
* *in\_payments\_offered*: The number of incoming HTLCs offered over this
  channel.
* *in\_offered\_msat*: A string describing the total amount of all incoming
  HTLCs offered over this channel;
  a number followed by a string unit.
* *in\_payments\_fulfilled*: The number of incoming HTLCs offered *and
  successfully claimed* over this channel.
* *in\_fulfilled\_msat*: A string describing the total amount of all
  incoming HTLCs offered *and successfully claimed* over this channel;
  a number followed by a string unit.
* *out\_payments\_offered*: The number of outgoing HTLCs offered over
  this channel.
* *out\_offered\_msat*: A string describing the total amount of all
  outgoing HTLCs offered over this channel;
  a number followed by a string unit.
* *out\_payments\_fulfilled*: The number of outgoing HTLCs offered *and
  successfully claimed* over this channel.
* *out\_fulfilled\_msat*: A string describing the total amount of all
  outgoing HTLCs offered *and successfully claimed* over this channel;
  a number followed by a string unit.
* *scratch\_txid*: The txid of the latest transaction (what we would sign and
  send to chain if the channel were to fail now).
* *last\_tx\_fee*: The fee on that latest transaction.
* *feerate*: An object containing the latest feerate as both *perkw* and *perkb*.
* *htlcs*: An array of objects describing the HTLCs currently in-flight
  in the channel.

Objects in the *htlcs* array will contain these fields:

* *direction*: Either the string `"out"` or `"in"`, whether it is an
  outgoing or incoming HTLC.
* *id*: A numeric ID uniquely identifying this HTLC.
* *amount\_msat*: The value of the HTLC.
* *expiry*: The blockheight at which the HTLC will be forced to return
  to its offerer: an `"in"` HTLC will be returned to the peer, an
  `"out"` HTLC will be returned to you.
  **NOTE** If the *expiry* of any outgoing HTLC will arrive in the next
  block, `lightningd`(8) will automatically unilaterally close the
  channel in order to enforce the timeout onchain.
* *payment\_hash*: The payment hash, whose preimage must be revealed to
  successfully claim this HTLC.
* *state*: A string describing whether the HTLC has been communicated to
  or from the peer, whether it has been signed in a new commitment, whether
  the previous commitment (that does not contain it) has been revoked, as
  well as when the HTLC is fulfilled or failed offchain.
* *local\_trimmed*: A boolean, existing and `true` if the HTLC is not
  actually instantiated as an output (i.e. "trimmed") on the commitment
  transaction (and will not be instantiated on a unilateral close).
  Generally true if the HTLC is below the *dust\_limit\_msat* for the
  channel.

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.

AUTHOR
------

Michael Hawkins <<michael.hawkins@protonmail.com>>.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel\_start(7),
lightning-setchannelfee(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning> Lightning
RFC site (BOLT \#9):
<https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md>

[comment]: # ( SHA256STAMP:adc1f36b764f1d98ba6a34b63f459a19db15fc94e37678806a1eb858a2166167)
