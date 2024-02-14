lightning-openchannel\_abort -- Command to abort a channel to a peer
====================================================================

SYNOPSIS
--------

**openchannel\_abort** *channel\_id* 

DESCRIPTION
-----------

`openchannel_init` is a low level RPC command which initiates a channel open with a specified peer. It uses the openchannel protocol which allows for interactive transaction construction.

- **channel\_id** (hash): Channel id of the channel to be aborted.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:openchannel_abort#1",
  "method": "openchannel_abort",
  "params": {
    "channel_id": "aec3dfd0c7643a23b679cd2e493c053f8fdf621ff2624949f9582c4118b818c6"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **channel\_id** (hash): The channel id of the aborted channel.
- **channel\_canceled** (boolean): Whether this is completely canceled (there may be remaining in-flight transactions).
- **reason** (string): Usually "Abort requested", but if it happened to fail at the same time it could be different.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "channel_id": "aec3dfd0c7643a23b679cd2e493c053f8fdf621ff2624949f9582c4118b818c6",
  "channel_canceled": true,
  "reason": "Abort requested"
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 305: Peer is not connected.
- 311: Unknown channel id.
- 312: Channel in an invalid state

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-openchannel\_init(7), lightning-openchannel\_update(7), lightning-openchannel\_signed(7), lightning-openchannel\_bump(7), lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7), lightning-fundchannel(7), lightning-fundpsbt(7), lightning-utxopsbt(7), lightning-multifundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
