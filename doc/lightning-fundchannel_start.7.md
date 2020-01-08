lightning-fundchannel\_start -- Command for initiating channel establishment for a lightning channel
====================================================================================================

SYNOPSIS
--------

**fundchannel\_start** *id* *amount* \[*feerate* *announce* *close_to* *push_msat*\]

DESCRIPTION
-----------

`fundchannel_start` is a lower level RPC command. It allows a user to
initiate channel establishment with a connected peer.

*id* is the node id of the remote peer.

*amount* is the satoshi value that the channel will be funded at. This
value MUST be accurate, otherwise the negotiated commitment transactions
will not encompass the correct channel value.

*feerate* is an optional field. Sets the feerate for subsequent
commitment transactions: see **fundchannel**.

*announce* whether or not to announce this channel.

*close_to* is a Bitcoin address to which the channel funds should be sent to
on close. Only valid if both peers have negotiated `option_upfront_shutdown_script`.
Returns `close_to` set to closing script iff is negotiated.

*push_msat* is the amount of millisatoshis to push to the channel peer at
open. Note that this is a gift to the peer -- these satoshis are
added to the initial balance of the peer at channel start and are largely
unrecoverable once pushed.

Note that the funding transaction MUST NOT be broadcast until after
channel establishment has been successfully completed by running
`fundchannel_complete`, as the commitment transactions for this channel
are not secured until the complete command succeeds. Broadcasting
transaction before that can lead to unrecoverable loss of funds.

RETURN VALUE
------------

On success, returns the *funding\_address* and the *scriptpubkey* for the channel funding output.
If a `close_to` address was provided, will close to this address iff the `close_to` address is
returned in the response. Otherwise, the peer does not support `option_upfront_shutdownscript`.

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 300: The amount exceeded the maximum configured funding amount.
- 301: The provided `push_msat` is greater than the provided `amount`.
- 304: Still syncing with bitcoin network
- 305: Peer is not connected.
- 306: Unknown peer id.

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
