lightning-close -- Command for closing channels with direct peers
=================================================================

SYNOPSIS
--------

**close** *id* \[*unilateraltimeout*\]

DESCRIPTION
-----------

The **close** RPC command attempts to close the channel cooperatively
with the peer, or unilaterally after *unilateraltimeout*.

If the given *id* is a peer ID (66 hex digits as a string), then it
applies to the active channel of the direct peer corresponding to the
given peer ID. If the given *id* is a channel ID (64 hex digits as a
string, or the short channel ID *blockheight:txindex:outindex* form),
then it applies to that channel.

If *unilateraltimeout* is not zero, the **close** command will
unilaterally close the channel when that number of seconds is reached.
If *unilateraltimeout* is zero, then the **close** command will wait
indefinitely until the peer is online and can negotiate a mutual close.
The default is 2 days (172800 seconds).

The peer needs to be live and connected in order to negotiate a mutual
close. The default of unilaterally closing after 48 hours is usually a
reasonable indication that you can no longer contact the peer.

NOTES
-----

Prior to 0.7.2, **close** took two parameters: *force* and *timeout*.
*timeout* was the number of seconds before *force* took effect (default,
30), and *force* determined whether the result was a unilateral close or
an RPC error (default). Even after the timeout, the channel would be
closed if the peer reconnected.

RETURN VALUE
------------

On success, an object with fields *tx* and *txid* containing the closing
transaction are returned. It will also have a field *type* which is
either the JSON string *mutual* or the JSON string *unilateral*. A
*mutual* close means that we could negotiate a close with the peer,
while a *unilateral* close means that the *force* flag was set and we
had to close the channel without waiting for the counterparty.

A unilateral close may still occur at any time if the peer did not
behave correctly during the close negotiation.

Unilateral closes will return your funds after a delay. The delay will
vary based on the peer *to\_self\_delay* setting, not your own setting.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-disconnect(7), lightning-fundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
