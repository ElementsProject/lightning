lightning-openchannel\_bump -- Command to initiate a channel RBF
=====================================================================

SYNOPSIS
--------

**openchannel\_bump** *channel\_id* *amount* *initalpsbt* [*funding\_feerate*]

DESCRIPTION
-----------

`openchannel_bump` is a RPC command which initiates a channel
RBF (Replace-By-Fee) for the specified channel. It uses the openchannel protocol
which allows for interactive transaction construction.

Warning: bumping a leased channel will lose the lease.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **channel\_id** (hex): the channel id of the channel (always 64 characters)
- **channel\_type** (object): channel\_type as negotiated with peer *(added v24.02)*:
  - **bits** (array of u32s): Each bit set in this channel\_type *(added v24.02)*:
    - Bit number
  - **names** (array of strings): Feature name for each bit set in this channel\_type *(added v24.02)*:
    - Name of feature bit (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even")
- **psbt** (string): the (incomplete) PSBT of the RBF transaction
- **commitments\_secured** (boolean): whether the *psbt* is complete (always *false*)
- **funding\_serial** (u64): the serial\_id of the funding output in the *psbt*
- **requires\_confirmed\_inputs** (boolean, optional): Does peer require confirmed inputs in psbt?

[comment]: # (GENERATE-FROM-SCHEMA-END)

If the peer does not support `option_dual_fund`, this command
will return an error.

If the channel is not in a state that is eligible for RBF, this command
will return an error.

ERRORS
------

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 300: The amount exceeded the maximum configured funding amount.
- 301: The provided PSBT cannot afford the funding amount.
- 305: Peer is not connected.
- 309: PSBT missing required fields
- 311: Unknown channel id.
- 312: Channel in an invalid state

SEE ALSO
--------

lightning-openchannel\_init(7), lightning-openchannel\_update(7),
lightning-openchannel\_signed(7), lightning-openchannel\_abort(7),
lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7),
lightning-fundchannel(7), lightning-fundpsbt(7), lightning-utxopsbt(7),
lightning-multifundchannel(7)

AUTHOR
------

@niftynei <<niftynei@gmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:98faf34f08ec57a266c82dfdb876f35d08187a16c1b6d53fedaa12570144a64f)
