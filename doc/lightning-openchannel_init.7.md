lightning-openchannel\_init -- Command to initiate a channel to a peer
=====================================================================

SYNOPSIS
--------

**openchannel_init** *id* *amount* *initalpsbt* \[*commitment_feerate*\] \[*funding_feerate*\] \[*announce*\] \[*close_to*\]

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

*commitment_feerate* is an optional field. Sets the feerate for
commitment transactions: see **fundchannel**.

*funding_feerate* is an optional field. Sets the feerate for the
funding transaction. Defaults to 'opening' feerate.

*announce* is an optional field. Whether or not to announce this channel.

*close_to* is a Bitcoin address to which the channel funds should be
sent on close. Only valid if both peers have negotiated
`option_upfront_shutdown_script`.


RETURN VALUE
------------

On success, returns the *channel_id* for this channel; an updated
incomplete *initialpsbt* for this funding transaction; and the flag
*commitments_secured*, which indiciates the completeness of the
passed back *psbt*. (Will always be false). Also returns the
*funding_serial*, indicating the serial\_id of the funding output
in the *psbt*.

If the peer does not support `option_dual_fund`, this command
will return an error.

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
lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7),
lightning-fundchannel(7), lightning-fundpsbt(7), lightning-utxopsbt(7),
lightning-multifundchannel(7)

AUTHOR
------

@niftynei <<niftynei@gmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
