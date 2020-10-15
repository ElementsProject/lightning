lightning-multifundchannel -- Command for establishing many lightning channels
==============================================================================

SYNOPSIS
--------

**multifundchannel** *destinations* \[*feerate*\] \[*minconf*\] \[*utxos*\] \[*minchannels*\] \[*commitment_feerate*\]

DESCRIPTION
-----------

The **multifundchannel** RPC command opens multiple payment channels
with nodes by committing a single funding transaction to the blockchain
that is shared by all channels.

If not already connected, **multifundchannel** will automatically attempt
to connect; you may provide a *@host:port* hint appended to the node ID
so that c-lightning can learn how to connect to the node;
see lightning-connect(7).

Once the transaction is confirmed, normal channel operations may begin.
Readiness is indicated by **listpeers** reporting a *state* of
`CHANNELD_NORMAL` for the channel.

*destinations* is an array of objects, with the fields:

* *id* is the node ID, with an optional *@host:port* appended to it
  in a manner understood by **connect**; see lightning-connect(7).
  Each entry in the *destinations* array must have a unique node *id*.
* *amount* is the amount in satoshis taken from the internal wallet
  to fund the channel.
  The string *all* can be used to specify all available funds
  (or 16,777,215 satoshi if more is available and large channels were
  not negotiated with the peer).
  Otherwise it is in satoshi precision; it can be
   a whole number,
   a whole number ending in *sat*,
   a whole number ending in *000msat*, or
   a number with 1 to 8 decimal places ending in *btc*.
  The value cannot be less than the dust limit, currently 546 satoshi
  as of this writing, nor more than 16,777,215 satoshi
  (unless large channels were negotiated with the peer).
* *announce* is an optional flag that indicates whether to announce
  the channel with this, default `true`.
  If set to `false`, the channel is unpublished.
* *push\_msat* is the amount of millisatoshis to outright give to the
  node.
  This is a gift to the peer, and you do not get a proof-of-payment
  out of this.
* *close_to* is a Bitcoin address to which the channel funds should be sent to
  on close. Only valid if both peers have negotiated
  `option_upfront_shutdown_script`.  Returns `close_to` set to
  closing script iff is negotiated.

There must be at least one entry in *destinations*;
it cannot be an empty array.

*feerate* is an optional feerate used for the opening transaction and, if
*commitment_feerate* is not set, as the initial feerate for
commitment and HTLC transactions. It can be one of
the strings *urgent* (aim for next block), *normal* (next 4 blocks or
so) or *slow* (next 100 blocks or so) to use lightningd’s internal
estimates: *normal* is the default.

Otherwise, *feerate* is a number, with an optional suffix: *perkw* means
the number is interpreted as satoshi-per-kilosipa (weight), and *perkb*
means it is interpreted bitcoind-style as satoshi-per-kilobyte. Omitting
the suffix is equivalent to *perkb*.

*minconf* specifies the minimum number of confirmations that used
outputs should have. Default is 1.

*utxos* specifies the utxos to be used to fund the channel, as an array
of "txid:vout".

*minchannels*, if specified, will re-attempt funding as long as at least
this many peers remain (must not be zero).
The **multifundchannel** command will only fail if too many peers fail
the funding process.

*commitment_feerate* is the initial feerate for commitment and HTLC
transactions. See *feerate* for valid values.

RETURN VALUE
------------

On success, the *tx* and *txid* of the signed and broadcsted funding
transaction is returned.
This command opens multiple channels with a single large transaction,
thus only one transaction is returned.

If *minchannels* was specified and is less than the number of destinations,
then it is possible that one or more of the destinations
do not have a channel even if **multifundchannel** succeeded.

An array of *channel\_ids* is returned;
each entry of the array is an object,
 with an *id* field being the node ID of the peer,
 an *outnum* field being the output number of the transaction
  that anchors this channel,
 and *channel_id* field being the channel ID with that peer.

An array of *failed* is returned,
which contains the destinations that were removed
due to failures (this can only happen on success if *minchannels* was specified).
Each entry of the array is an object,
 with an *id* field being the node ID of the removed peer,
 *method* field describing what phase of funding the peer failed,
 and *error* field of the exact error returned by the method.

On failure, none of the channels are created.

The following error codes may occur:
* -1: Catchall nonspecific error.
- 300: The maximum allowed funding amount is exceeded.
- 301: There are not enough funds in the internal wallet (including fees) to create the transaction.
- 302: The output amount is too small, and would be considered dust.
- 303: Broadcasting of the funding transaction failed, the internal call to bitcoin-cli returned with an error.

Failure may also occur if **lightningd** and the peer cannot agree on
channel parameters (funding limits, channel reserves, fees, etc.).
See lightning-fundchannel\_start(7) and lightning-fundchannel\_complete(7).

There may be rare edge cases where a communications failure later in
the channel funding process will cancel the funding locally, but
the peer thinks the channel is already waiting for funding lockin.
In that case, the next time we connect to the peer, our node will
tell the peer to forget the channel, but some nodes (in particular,
c-lightning nodes) will disconnect when our node tells them to
forget the channel.
If you immediately **multifundchannel** with that peer, it could
trigger this connect-forget-disconnect behavior, causing the
second **multifundchannel** to fail as well due to disconnection.
Doing a **connect** with the peers separately, and waiting for a
few seconds, should help clear this hurdle;
running **multifundchannel** a third time would also clear this.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-listfunds(), lightning-listpeers(7),
lightning-fundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
