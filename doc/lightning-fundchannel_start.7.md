LIGHTNING-FUNDCHANNEL\_START(7) Manual Page
===========================================
lightning-fundchannel\_start - Command for initiating channel
establishment for a lightning channel

SYNOPSIS
--------

**fundchannel\_start** *id* *satoshi* \[*feerate* *announce*\]

DESCRIPTION
-----------

`fundchannel_start` is a lower level RPC command. It allows a user to
initiate channel establishment with a connected peer.

*id* is the node id of the remote peer.

*satoshi* is the satoshi value that the channel will be funded at. This
value MUST be accurate, otherwise the negotiated commitment transactions
will not encompass the correct channel value.

*feerate* is an optional field. Sets the feerate for subsequent
commitment transactions.

*announce* whether or not to annouce this channel.

RETURN VALUE
------------

On success, returns the *funding\_address* for the channel.

On failure, returns an error.

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel(7),
lightning-fundchannel\_complete(7), lightning-fundchannel\_cancel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

------------------------------------------------------------------------

Last updated 2019-06-12 11:16:20 CEST
