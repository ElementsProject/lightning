lightning-openchannel\_bump -- Command to initiate a channel RBF
=====================================================================

SYNOPSIS
--------

**openchannel_bump** *channel_id* *amount* *initalpsbt* [*funding_feerate*]

DESCRIPTION
-----------

`openchannel_bump` is a RPC command which initiates a channel
RBF (Replace-By-Fee) for the specified channel. It uses the openchannel protocol
which allows for interactive transaction construction.

*id* is the id of the channel to RBF.

*amount* is the satoshi value that we will contribute to the channel.
This value will be _added_ to the provided PSBT in the output which is
encumbered by the 2-of-2 script for this channel.

*initialpsbt* is the funded, incomplete PSBT that specifies the UTXOs and
change output for our channel contribution. It can be updated,
see `openchannel_update`; *initialpsbt* must have at least one input.
Must have the Non-Witness UTXO (PSBT\_IN\_NON\_WITNESS\_UTXO) set for
every input. An error (code 309) will be returned if this requirement
is not met.

*funding_feerate* is an optional field. Sets the feerate for the
funding transaction. Defaults to 1/64th greater than the last
feerate used for this channel.

Warning: bumping a leased channel will lose the lease.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **channel_id** (hex): the channel id of the channel (always 64 characters)
- **psbt** (string): the (incomplete) PSBT of the RBF transaction
- **commitments_secured** (boolean): whether the *psbt* is complete (always *false*)
- **funding_serial** (u64): the serial_id of the funding output in the *psbt*

[comment]: # (GENERATE-FROM-SCHEMA-END)

If the peer does not support `option_dual_fund`, this command
will return an error.

If the channel is not in a state that is eligible for RBF, this command
will return an error.

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
[comment]: # ( SHA256STAMP:0b3c4fc19cdad9162b91585c4af2dc5293ecd8925628d10b612cd777dcdedeea)
