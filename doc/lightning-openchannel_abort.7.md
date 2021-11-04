lightning-openchannel\_abort -- Command to abort a channel to a peer
=====================================================================

SYNOPSIS
--------

**openchannel_abort** *channel_id*

DESCRIPTION
-----------

`openchannel_init` is a low level RPC command which initiates a channel
open with a specified peer. It uses the openchannel protocol
which allows for interactive transaction construction.

*channel_id* is id of this channel.


RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **channel_id** (hex): the channel id of the aborted channel (always 64 characters)
- **channel_canceled** (boolean): whether this is completely canceled (there may be remaining in-flight transactions)
- **reason** (string): usually "Abort requested", but if it happened to fail at the same time it could be different

[comment]: # (GENERATE-FROM-SCHEMA-END)

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 305: Peer is not connected.
- 311: Unknown channel id.
- 312: Channel in an invalid state

SEE ALSO
--------

lightning-openchannel\_init(7), lightning-openchannel\_update(7),
lightning-openchannel\_signed(7), lightning-openchannel\_bump(7),
lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7),
lightning-fundchannel(7), lightning-fundpsbt(7), lightning-utxopsbt(7),
lightning-multifundchannel(7)

AUTHOR
------

@niftynei <<niftynei@gmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:78d6fbc1044e3a499ca618ea71845aa04043f46c169f4f50763644c7a3e35572)
