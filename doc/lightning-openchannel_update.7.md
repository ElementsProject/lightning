lightning-openchannel\_update -- Command to update a collab channel open
========================================================================

SYNOPSIS
--------

**openchannel_update** *id* *psbt*

DESCRIPTION
-----------

`openchannel_update` is a low level RPC command which continues an open
channel with peer, as specified by *id*. An updated  *psbt* is passed in; any
changes from the PSBT last returned (either from `openchannel_init` or
a previous call to `openchannel_update`) will be communicated to the peer.

Must be called after `openchannel_init` and before `openchannel_signed`.

Must be called until *commitments_secured* is returned as true, at which point
`openchannel_signed` should be called with a signed version of the PSBT
returned by the last call to `openchannel_update`.

*id* is the node id of the remote peer.

*psbt* is the updated PSBT to be sent to the peer. May be identical to
the PSBT last returned by either `openchannel_init` or `openchannel_update`.

RETURN VALUE
------------

On success, returns the *channel_id* for this channel; an updated, potentially
complete *psbt* for this channel's funding transaction; and the flag
*commitments_secured*, which indicates the completeness of the returned *psbt*.
If *commitments_secured* is true, caller should proceed with signing the
returned PSBT and calling `openchannel_signed` to complete the channel open.

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 305: Peer is not connected.
- 306: Unknown peer id.
- 309: PSBT missing required fields

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
