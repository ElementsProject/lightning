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

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **cancelled** (string): A message indicating it was cancelled by RPC

[comment]: # (GENERATE-FROM-SCHEMA-END)

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- 306: Unknown peer id.
- 307: No channel currently being funded that can be cancelled.
- 308: It is unsafe to cancel the channel: the funding transaction
  has been broadcast, or there are HTLCs already in the channel, or
  the peer was the initiator and not us.

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel(7), lightning-multifundchannel(7),
lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7)
lightning-openchannel\_init(7), lightning-openchannel\_update(7),
lightning-openchannel\_signed(7), lightning-openchannel\_abort(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:8b0f33ba88ad83b91b4f574b1a6320690bf5cd2fdb4cc731691a8be62edb7671)
