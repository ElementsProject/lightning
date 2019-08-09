lightning-fundchannel\_complete

7

lightning-fundchannel\_complete

Command for completing channel establishment

**fundchannel\_complete** *id* *txid* *txout*

DESCRIPTION
===========

`fundchannel_complete` is a lower level RPC command. It allows a user to
complete an initiated channel establishment with a connected peer

*id* is the node id of the remote peer

*txid* is the hex string of the funding transaction id.

*txout* is the integer outpoint of the funding output for this channel.

Note that the funding transaction should not be broadcast until after
channel establishment has been successfully completed, as the commitment
transactions for this channel are not secured until this command
succesfully completes.

RETURN VALUE
============

On success, returns a confirmation that *commitments\_secured* and the
derived *channel\_id*.

On failure, returns an error.

AUTHOR
======

Lisa Neigut &lt;<niftynei@gmail.com>&gt; is mainly responsible.

SEE ALSO
========

lightning-connect(7), lightning-fundchannel(7),
lightning-fundchannel\_start(7), lightning-fundchannel\_cancel(7)

RESOURCES
=========

Main web site: <https://github.com/ElementsProject/lightning>
