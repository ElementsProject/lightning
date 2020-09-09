lightning-fundchannel -- Command for establishing a lightning channel
=====================================================================

SYNOPSIS
--------

**fundchannel** *id* *amount* \[*feerate* *announce*\] \[*minconf*\]
\[*utxos*\] \[*push_msat*\]

DESCRIPTION
-----------

The **fundchannel** RPC command opens a payment channel with a peer by
committing a funding transaction to the blockchain as defined in BOLT
\#2.
If not already connected, **fundchannel** will automatically attempt
to connect if C-lightning knows a way to contact the node (either from
normal gossip, or from a previous **connect** call).
This auto-connection can fail if C-lightning does not know how to contact
the target node; see lightning-connect(7).
Once the
transaction is confirmed, normal channel operations may begin. Readiness
is indicated by **listpeers** reporting a *state* of `CHANNELD_NORMAL`
for the channel.

*id* is the peer id obtained from **connect**.

*amount* is the amount in satoshis taken from the internal wallet to
fund the channel. The string *all* can be used to specify all available
funds (or 16777215 satoshi if more is available and large channels were not negotiated with the peer). Otherwise, it is in
satoshi precision; it can be a whole number, a whole number ending in
*sat*, a whole number ending in *000msat*, or a number with 1 to 8
decimal places ending in *btc*. The value cannot be less than the dust
limit, currently set to 546, nor more than 16777215 satoshi (unless large
channels were negotiated with the peer).

*feerate* is an optional feerate used for the opening transaction and as
initial feerate for commitment and HTLC transactions. It can be one of
the strings *urgent* (aim for next block), *normal* (next 4 blocks or
so) or *slow* (next 100 blocks or so) to use lightningd’s internal
estimates: *normal* is the default.

Otherwise, *feerate* is a number, with an optional suffix: *perkw* means
the number is interpreted as satoshi-per-kilosipa (weight), and *perkb*
means it is interpreted bitcoind-style as satoshi-per-kilobyte. Omitting
the suffix is equivalent to *perkb*.

*announce* is an optional flag that triggers whether to announce this
channel or not. Defaults to `true`. An unannounced channel is considered
private.

*minconf* specifies the minimum number of confirmations that used
outputs should have. Default is 1.

*utxos* specifies the utxos to be used to fund the channel, as an array
of "txid:vout".

*push_msat* is the amount of millisatoshis to push to the channel peer at
open. Note that this is a gift to the peer -- these satoshis are
added to the initial balance of the peer at channel start and are largely
unrecoverable once pushed.

RETURN VALUE
------------

On success, the *tx* and *txid* of the transaction is returned, as well
as the *outnum* indicating the output index which creates the channel, as well
as the *channel\_id* of the newly created channel. On failure, an error
is reported and the channel is not funded.

The following error codes may occur:
- -1: Catchall nonspecific error.
- 300: The maximum allowed funding amount is exceeded.
- 301: There are not enough funds in the internal wallet (including fees) to create the transaction.
- 302: The output amount is too small, and would be considered dust.
- 303: Broadcasting of the funding transaction failed, the internal call to bitcoin-cli returned with an error.

Failure may also occur if **lightningd** and the peer cannot agree on
channel parameters (funding limits, channel reserves, fees, etc.).

SEE ALSO
--------

lightning-connect(7), lightning-listfunds(), lightning-listpeers(7),
lightning-feerates(7), lightning-multifundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

