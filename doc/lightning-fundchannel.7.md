lightning-fundchannel -- Command for establishing a lightning channel
=====================================================================

SYNOPSIS
--------

**fundchannel** *id* *amount* [*feerate*] [*announce*] [*minconf*]
[*utxos*] [*push\_msat*] [*close\_to*] [*request\_amt*] [*compact\_lease*]
[*reserve*] [*channel\_type*]

DESCRIPTION
-----------

The **fundchannel** RPC command opens a payment channel with a peer by committing a 
funding transaction to the blockchain as defined in BOLT #2.

If not already connected, **fundchannel** will automatically attempt to connect if 
Core Lightning knows a way to contact the node (either from normal gossip, or from 
a previous **connect** call).

This auto-connection can fail if Core Lightning does not know how to contact the 
target node; see lightning-connect(7).

*feerate* is an optional feerate used for the opening transaction and
(unless *option\_anchors\_zero\_fee\_htlc\_tx* is negotiated), as initial feerate
for commitment and HTLC transactions (see NOTES in lightning-feerates(7)).
The default is *normal*.

*announce* is an optional flag that triggers whether to announce this
channel or not. Defaults to `true`. An unannounced channel is considered
private.

*minconf* specifies the minimum number of confirmations that used
outputs should have. Default is 1.

*utxos* specifies the utxos to be used to fund the channel, as an array
of "txid:vout".

*push\_msat* is the amount of millisatoshis to push to the channel peer at
open. Note that this is a gift to the peer -- these satoshis are
added to the initial balance of the peer at channel start and are largely
unrecoverable once pushed.

*close\_to* is a Bitcoin address to which the channel funds should be sent to
on close. Only valid if both peers have negotiated `option_upfront_shutdown_script`.
Returns `close_to` set to closing script iff is negotiated.

*request\_amt* is an amount of liquidity you'd like to lease from the peer.
If peer supports `option_will_fund`, indicates to them to include this
much liquidity into the channel. Must also pass in *compact\_lease*.

*compact\_lease* is a compact representation of the peer's expected
channel lease terms. If the peer's terms don't match this set, we will
fail to open the channel.

*reserve* is the amount we want the peer to maintain on its side of the channel.
Default is 1% of the funding amount. It can be a whole number, a whole number
ending in *sat*, a whole number ending in *000msat*, or a number with 1 to 8
decimal places ending in *btc*.

*channel\_type* *(added v24.02)* is an array of bit numbers, representing the explicit
channel type to request.  There is currently no sanity checking on
this value so if you use strange values and your channel breaks, you
get to keep both pieces.  BOLT 2 defines the following value types:

```
The currently defined basic types are:
  - no features (no bits set)
  - `option_static_remotekey` (bit 12)
  - `option_anchor_outputs` and `option_static_remotekey` (bits 20 and 12)
  - `option_anchors_zero_fee_htlc_tx` and `option_static_remotekey` (bits 22 and 12)

Each basic type has the following variations allowed:
  - `option_scid_alias` (bit 46)
  - `option_zeroconf` (bit 50)
```

EXAMPLE
-------

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
- **channel\_id** (hex): The channel\_id of the resulting channel (always 64 characters)
- **channel\_type** (object): channel\_type as negotiated with peer *(added v24.02)*:
  - **bits** (array of u32s): Each bit set in this channel\_type *(added v24.02)*:
    - Bit number
  - **names** (array of strings): Feature name for each bit set in this channel\_type *(added v24.02)*:
    - Name of feature bit (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even")
- **close\_to** (hex, optional): The raw scriptPubkey which mutual close will go to; only present if *close\_to* parameter was specified and peer supports `option_upfront_shutdown_script`
- **mindepth** (u32, optional): Number of confirmations before we consider the channel active.

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
-------

The following error codes may occur:

- -1: Catchall nonspecific error.
- 300: The maximum allowed funding amount is exceeded.
- 301: There are not enough funds in the internal wallet (including fees) to create the transaction.
- 302: The output amount is too small, and would be considered dust.
- 303: Broadcasting of the funding transaction failed, the internal call to bitcoin-cli returned with an error.
- 313: The `min-emergency-msat` reserve not be preserved (and we have or are opening anchor channels).

Failure may also occur if **lightningd** and the peer cannot agree on
channel parameters (funding limits, channel reserves, fees, etc.).

SEE ALSO
--------

lightning-connect(7), lightning-listfunds(), lightning-listpeers(7),
lightning-feerates(7), lightning-multifundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:b890bd25970e8e1ef92812daa89a25ded100173f9ab411492a87d6cd268ee32d)
