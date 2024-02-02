lightning-fundchannel\_complete -- Command for completing channel establishment
===============================================================================

SYNOPSIS
--------

**fundchannel\_complete** *id* *psbt*

DESCRIPTION
-----------

`fundchannel_complete` is a lower level RPC command. It allows a user to
complete an initiated channel establishment with a connected peer.

Note that the funding transaction MUST NOT be broadcast until after
channel establishment has been successfully completed, as the commitment
transactions for this channel are not secured until this command
successfully completes. Broadcasting transaction before can lead to
unrecoverable loss of funds.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **channel\_id** (hex): The channel\_id of the resulting channel (always 64 characters)
- **commitments\_secured** (boolean): Indication that channel is safe to use (always *true*)

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 305: Peer is not connected.
- 306: Unknown peer id.
- 309: PSBT does not have a unique, correct output to fund the channel.

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel(7), lightning-multifundchannel(7),
lightning-fundchannel\_start(7), lightning-fundchannel\_cancel(7),
lightning-openchannel\_init(7), lightning-openchannel\_update(7),
lightning-openchannel\_signed(7), lightning-openchannel\_bump(7),
lightning-openchannel\_abort(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:68a03c118fd7851c8025f52f52393d108d26e1045e126cd194e7605867114b24)
