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

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **channel\_id** (hex): the channel id of the channel (always 64 characters)
- **psbt** (string): the (incomplete) PSBT of the funding transaction
- **channel\_type** (object): channel\_type as negotiated with peer *(added v24.02)*:
  - **bits** (array of u32s): Each bit set in this channel\_type *(added v24.02)*:
    - Bit number
  - **names** (array of strings): Feature name for each bit set in this channel\_type *(added v24.02)*:
    - Name of feature bit (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even")
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

ERRORS
------

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

[comment]: # ( SHA256STAMP:2815e0b486c5346d0d058a7670b7e34f55b7ce0f5d35861dd76316e42b7b589d)
