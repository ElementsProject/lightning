lightning-fundchannel -- Command for establishing a lightning channel
=====================================================================

SYNOPSIS
--------

**fundchannel** *id* *amount* [*feerate*] [*announce*] [*minconf*]
[*utxos*] [*push_msat*] [*close_to*] [*request_amt*] [*compact_lease*]

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
so) or *slow* (next 100 blocks or so) to use lightningd's internal
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

*close_to* is a Bitcoin address to which the channel funds should be sent to
on close. Only valid if both peers have negotiated `option_upfront_shutdown_script`.
Returns `close_to` set to closing script iff is negotiated.

*request_amt* is an amount of liquidity you'd like to lease from the peer.
If peer supports `option_will_fund`, indicates to them to include this
much liquidity into the channel. Must also pass in *compact_lease*.

*compact_lease* is a compact represenation of the peer's expected
channel lease terms. If the peer's terms don't match this set, we will
fail to open the channel.



This example shows how to use lightning-cli to open new channel with peer 03f...fc1 from one whole utxo bcc1...39c:0
(you can use **listfunds** command to get txid and vout):

	lightning-cli -k fundchannel id=03f...fc1 amount=all feerate=normal utxos='["bcc1...39c:0"]'

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **tx** (hex): The raw transaction which funded the channel
- **txid** (txid): The txid of the transaction which funded the channel
- **outnum** (u32): The 0-based output index showing which output funded the channel
- **channel_id** (hex): The channel_id of the resulting channel (always 64 characters)
- **close_to** (hex, optional): The raw scriptPubkey which mutual close will go to; only present if *close_to* parameter was specified and peer supports `option_upfront_shutdown_script`

[comment]: # (GENERATE-FROM-SCHEMA-END)

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

[comment]: # ( SHA256STAMP:4a8d7c524cfe257f961531929d14d3589efb6ecd182a33e92aade30af90406f8)
