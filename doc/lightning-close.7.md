lightning-close -- Command for closing channels with direct peers
=================================================================

SYNOPSIS
--------

**close** *id* [*unilateraltimeout*] [*destination*] [*fee\_negotiation\_step*] [*wrong\_funding*] [*force\_lease\_closed*] [*feerange*]

DESCRIPTION
-----------

The **close** RPC command attempts to close the channel cooperatively
with the peer, or unilaterally after *unilateraltimeout*, and the
to-local output will be sent to the address specified in *destination*.

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

NOTIFICATIONS
-------------

Notifications may be returned indicating what is going on, especially
if the peer is offline and we are waiting.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **type** (string): Whether we successfully negotiated a mutual close, closed without them, or discarded not-yet-opened channel (one of "mutual", "unilateral", "unopened")

If **type** is "mutual" or "unilateral":

  - **tx** (hex): the raw bitcoin transaction used to close the channel (if it was open)
  - **txid** (txid): the transaction id of the *tx* field

[comment]: # (GENERATE-FROM-SCHEMA-END)

A unilateral close may still occur at any time if the peer did not
behave correctly during the close negotiation.

Unilateral closes will return your funds after a delay. The delay will
vary based on the peer *to\_self\_delay* setting, not your own setting.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-disconnect(7), lightning-fundchannel(7), lightningd-config(5).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:958a08abbec73812611f72c25b656bc6095fe1d9ff7b5447d0da661151335871)
