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

On success, returns the *channel_id* for this channel; an boolean indicating
if the channel has been successfully canceled, *channel_canceled*;
a reason for the cancellation, *reason*.

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
