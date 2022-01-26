lightning-multifundchannel -- Command for establishing many lightning channels
==============================================================================

SYNOPSIS
--------

**multifundchannel** *destinations* [*feerate*] [*minconf*] [*utxos*] [*minchannels*] [*commitment_feerate*]

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
* *request_amt* is the amount of liquidity you'd like to lease from peer.
  If peer supports `option_will_fund`, indicates to them to include this
  much liquidity into the channel. Must also pass in *compact_lease*.
* *compact_lease* is a compact represenation of the peer's expected
  channel lease terms. If the peer's terms don't match this set, we will
  fail to open the channel to this destination.

There must be at least one entry in *destinations*;
it cannot be an empty array.

*feerate* is an optional feerate used for the opening transaction and, if
*commitment_feerate* is not set, as the initial feerate for
commitment and HTLC transactions. It can be one of
the strings *urgent* (aim for next block), *normal* (next 4 blocks or
so) or *slow* (next 100 blocks or so) to use lightningd's internal
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

This command opens multiple channels with a single large transaction,
thus only one transaction is returned.

If *minchannels* was specified and is less than the number of destinations,
then it is possible that one or more of the destinations
do not have a channel even if **multifundchannel** succeeded.

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **tx** (hex): The raw transaction which funded the channel
- **txid** (txid): The txid of the transaction which funded the channel
- **channel_ids** (array of objects):
  - **id** (pubkey): The peer we opened the channel with
  - **outnum** (u32): The 0-based output index showing which output funded the channel
  - **channel_id** (hex): The channel_id of the resulting channel (always 64 characters)
  - **close_to** (hex, optional): The raw scriptPubkey which mutual close will go to; only present if *close_to* parameter was specified and peer supports `option_upfront_shutdown_script`
- **failed** (array of objects, optional): any peers we failed to open with (if *minchannels* was specified less than the number of destinations):
  - **id** (pubkey): The peer we failed to open the channel with
  - **method** (string): What stage we failed at (one of "connect", "openchannel_init", "fundchannel_start", "fundchannel_complete")
  - **error** (object):
    - **code** (integer): JSON error code from failing stage
    - **message** (string): Message from stage
    - **data**: Additional error data

[comment]: # (GENERATE-FROM-SCHEMA-END)

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
[comment]: # ( SHA256STAMP:a6358ad8d361ae4104c727e6b8ab342923a613b78d5f13552794f827a1125e8b)
