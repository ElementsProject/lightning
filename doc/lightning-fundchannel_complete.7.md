lightning-fundchannel\_complete -- Command for completing channel establishment
===============================================================================

SYNOPSIS
--------

**fundchannel\_complete** *id* *txid* *txout*

DESCRIPTION
-----------

`fundchannel_complete` is a lower level RPC command. It allows a user to
complete an initiated channel establishment with a connected peer.

*id* is the node id of the remote peer.

*txid* is the hex string of the funding transaction id.

*txout* is the integer outpoint of the funding output for this channel.

Note that the funding transaction MUST NOT be broadcast until after
channel establishment has been successfully completed, as the commitment
transactions for this channel are not secured until this command
successfully completes. Broadcasting transaction before can lead to
unrecoverable loss of funds.

RETURN VALUE
------------

On success, returns a confirmation that *commitments\_secured* and the
derived *channel\_id*.

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 305: Peer is not connected.
- 306: Unknown peer id.

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

