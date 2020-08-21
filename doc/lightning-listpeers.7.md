lightning-listpeers -- Command returning data on connected lightning nodes
==========================================================================

SYNOPSIS
--------

**listpeers** \[*id*\] \[*level*\]

DESCRIPTION
-----------

The **listpeers** RPC command returns data on nodes that are connected
or are not connected but have open channels with this node.

Once a connection to another lightning node has been established, using
the **connect** command, data on the node can be returned using
**listpeers** and the *id* that was used with the **connect** command.

If no *id* is supplied, then data on all lightning nodes that are
connected, or not connected but have open channels with this node, are
returned.

Supplying *id* will filter the results to only return data on a node
with a matching *id*, if one exists.

Supplying *level* will show log entries related to that peer at the
given log level. Valid log levels are "io", "debug", "info", and
"unusual".

If a channel is open with a node and the connection has been lost, then
the node will still appear in the output of the command and the value of
the *connected* attribute of the node will be "false".

The channel will remain open for a set blocktime, after which if the
connection has not been re-established, the channel will close and the
node will no longer appear in the command output.

RETURN VALUE
------------

On success, an object with a "peers" key is returned containing a list
of 0 or more objects.

Each object in the list contains the following data:
- *id* : The unique id of the peer
- *connected* : A boolean value showing the connection status
- *netaddr* : A list of network addresses the node is listening on
- *features* : Bit flags showing supported features (BOLT \#9)
- *channels* : An array of objects describing channels with the peer.
- *log* : Only present if *level* is set. List logs related to the
peer at the specified *level*

If *id* is supplied and no matching nodes are found, a "peers" object
with an empty list is returned.

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
* *in\_payments_offered*: The number of incoming HTLCs offered over this
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

lightning-connect(7), lightning-fundchannel\_start(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning> Lightning
RFC site (BOLT \#9):
<https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md>
