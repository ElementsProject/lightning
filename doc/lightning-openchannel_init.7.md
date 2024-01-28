lightning-openchannel\_init -- Command to initiate a channel to a peer
=====================================================================

SYNOPSIS
--------

**openchannel\_init** *id* *amount* *initalpsbt* [*commitment\_feerate*] [*funding\_feerate*] [*announce*] [*close\_to*] [*request\_amt*] [*compact\_lease*] [*channel\_type*]

DESCRIPTION
-----------

`openchannel_init` is a low level RPC command which initiates a channel
open with a specified peer. It uses the openchannel protocol
which allows for interactive transaction construction.

*id* is the node id of the remote peer.

*amount* is the satoshi value that we will contribute to the channel.
This value will be _added_ to the provided PSBT in the output which is
encumbered by the 2-of-2 script for this channel.

*initialpsbt* is the funded, incomplete PSBT that specifies the UTXOs and
change output for our channel contribution. It can be updated,
see `openchannel_update`; *initialpsbt* must have at least one input.
Must have the Non-Witness UTXO (PSBT\_IN\_NON\_WITNESS\_UTXO) set for
every input. An error (code 309) will be returned if this requirement
is not met.

*commitment\_feerate* is an optional field. Sets the feerate for
commitment transactions for non-anchor channels: see **fundchannel**.
For anchor channels, it is ignored.

*funding\_feerate* is an optional field. Sets the feerate for the
funding transaction. Defaults to 'opening' feerate.

*announce* is an optional field. Whether or not to announce this channel.

*close\_to* is a Bitcoin address to which the channel funds should be
sent on close. Only valid if both peers have negotiated
`option_upfront_shutdown_script`.

*request\_amt* is an amount of liquidity you'd like to lease from the peer.
If peer supports `option_will_fund`, indicates to them to include this
much liquidity into the channel. Must also pass in *compact\_lease*.

*compact\_lease* is a compact represenation of the peer's expected
channel lease terms. If the peer's terms don't match this set, we will
fail to open the channel.

*channel\_type* *(added v24.02)* is an array of bit numbers, representing the explicit
channel type to request.  BOLT 2 defines the following value types:

The currently defined basic types are:
  - no features (no bits set) `[]`
  - `option_static_remotekey` (`[12]`)
  - `option_anchor_outputs` and `option_static_remotekey` (`[20, 12]`)
  - `option_anchors_zero_fee_htlc_tx` and `option_static_remotekey` ([22, 12])

Each basic type has the following variations allowed:
  - `option_scid_alias` ([46])
  - `option_zeroconf` ([50])
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **channel\_id** (hex): the channel id of the channel (always 64 characters)
- **psbt** (string): the (incomplete) PSBT of the funding transaction
- **commitments\_secured** (boolean): whether the *psbt* is complete (always *false*)
- **funding\_serial** (u64): the serial\_id of the funding output in the *psbt*
- **requires\_confirmed\_inputs** (boolean, optional): Does peer require confirmed inputs in psbt?

[comment]: # (GENERATE-FROM-SCHEMA-END)

If the peer does not support `option_dual_fund`, this command
will return an error.

If you sent a *request\_amt* and the peer supports `option_will_fund` and is
interested in leasing you liquidity in this channel, returns their updated
channel fee max (*channel\_fee\_proportional\_basis*, *channel\_fee\_base\_msat*),
updated rate card for the lease fee (*lease\_fee\_proportional\_basis*,
*lease\_fee\_base\_sat*) and their on-chain weight *weight\_charge*, which will
be added to the lease fee at a rate of *funding\_feerate* * *weight\_charge*
/ 1000.

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 300: The amount exceeded the maximum configured funding amount.
- 301: The provided PSBT cannot afford the funding amount.
- 304: Still syncing with bitcoin network
- 305: Peer is not connected.
- 306: Unknown peer id.
- 309: PSBT missing required fields
- 310: v2 channel open protocol not supported by peer
- 312: Channel in an invalid state

SEE ALSO
--------

lightning-openchannel\_update(7), lightning-openchannel\_signed(7),
lightning-openchannel\_abort(7), lightning-openchannel\_bump(7),
lightning-fundchannel\_start(7),
lightning-fundchannel\_complete(7), lightning-fundchannel(7),
lightning-fundpsbt(7), lightning-utxopsbt(7), lightning-multifundchannel(7)

AUTHOR
------

@niftynei <<niftynei@gmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:71a3f74f3cb3325a51f4d998675a0d8fd01de20d1f3326c553789066bcf8c3a1)
