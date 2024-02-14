lightning-fundchannel\_cancel -- Command for completing channel establishment
=============================================================================

SYNOPSIS
--------

**fundchannel\_cancel** *id* 

DESCRIPTION
-----------

`fundchannel_cancel` is a lower level RPC command. It allows channel opener to cancel a channel before funding broadcast with a connected peer.

Note that the funding transaction MUST NOT be broadcast before `fundchannel_cancel`. Broadcasting transaction before `fundchannel_cancel` WILL lead to unrecoverable loss of funds.

If `fundchannel_cancel` is called after `fundchannel_complete`, the remote peer may disconnect when command succeeds. In this case, user need to connect to remote peer again before opening channel.

- **id** (pubkey): Node id of the remote peer with which to cancel.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:fundchannel_cancel#1",
  "method": "fundchannel_cancel",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59"
  }
}
{
  "id": "example:fundchannel_cancel#2",
  "method": "fundchannel_cancel",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **cancelled** (string): A message indicating it was cancelled by RPC.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "cancelled": "Channel open canceled by RPC"
}
{
  "cancelled": "Channel open canceled by RPC(after fundchannel_complete)"
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.
- 306: Unknown peer id.
- 307: No channel currently being funded that can be cancelled.
- 308: It is unsafe to cancel the channel: the funding transaction has been broadcast, or there are HTLCs already in the channel, or the peer was the initiator and not us.

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel(7), lightning-multifundchannel(7), lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7), lightning-openchannel\_init(7), lightning-openchannel\_update(7), lightning-openchannel\_signed(7), lightning-openchannel\_abort(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
