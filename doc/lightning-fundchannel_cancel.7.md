lightning-fundchannel\_cancel -- Command for completing channel establishment
=============================================================================

SYNOPSIS
--------

**fundchannel\_cancel** *id*

DESCRIPTION
-----------

`fundchannel_cancel` is a lower level RPC command. It allows channel opener
to cancel a channel before funding broadcast with a connected peer.

*id* is the node id of the remote peer with which to cancel.

Note that the funding transaction MUST NOT be broadcast before
`fundchannel_cancel`. Broadcasting transaction before `fundchannel_cancel`
WILL lead to unrecoverable loss of funds.

If `fundchannel_cancel` is called after `fundchannel_complete`, the remote
peer may disconnect when command succeeds. In this case, user need to connect
to remote peer again before opening channel.

RETURN VALUE
------------

On success, returns confirmation that the channel establishment has been
canceled.

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 306: Unknown peer id.

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel(7),
lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
