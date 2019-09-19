lightning-fundchannel\_start -- Command for initiating channel establishment for a lightning channel
====================================================================================================

SYNOPSIS
--------

**fundchannel\_start** *id* *amount* \[*feerate* *announce*\]

DESCRIPTION
-----------

`fundchannel_start` is a lower level RPC command. It allows a user to
initiate channel establishment with a connected peer.

*id* is the node id of the remote peer.

*amount* is the satoshi value that the channel will be funded at. This
value MUST be accurate, otherwise the negotiated commitment transactions
will not encompass the correct channel value.

*feerate* is an optional field. Sets the feerate for subsequent
commitment transactions.

*announce* whether or not to announce this channel.

Note that the funding transaction MUST NOT be broadcast until after
channel establishment has been successfully completed by running
`fundchannel_complete`, as the commitment transactions for this channel
are not secured until the complete command succeeds. Broadcasting
transaction before that can lead to unrecoverable loss of funds.

RETURN VALUE
------------

On success, returns the *funding\_address* and the *scriptpubkey* for the channel funding output.

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
