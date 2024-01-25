lightning-close -- Command for closing channels with direct peers
=================================================================

SYNOPSIS
--------

**close** *id* [*unilateraltimeout*] [*destination*] [*fee\_negotiation\_step*] [*wrong\_funding*] [*force\_lease\_closed*] [\*feerange\*]

DESCRIPTION
-----------

The **close** RPC command attempts to close the channel cooperatively
with the peer, or unilaterally after *unilateraltimeout*, and the
to-local output will be sent to the address specified in *destination*.

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

The *destination* can be of any Bitcoin bech32 type.
If it isn't specified, the default is a Core Lightning wallet address.  If
the peer hasn't offered the `option_shutdown_anysegwit` feature, then
taproot addresses (or other v1+ segwit) are not allowed.  Tell your
friends to upgrade!

The *fee\_negotiation\_step* parameter controls how closing fee
negotiation is performed assuming the peer proposes a fee that is
different than our estimate.  (Note that modern peers use the quick-close protocol which does not allow negotiation: see *feerange* instead).

On every negotiation step we must give up
some amount from our proposal towards the peer's proposal. This parameter
can be an integer in which case it is interpreted as number of satoshis
to step at a time. Or it can be an integer followed by "%" to designate
a percentage of the interval to give up. A few examples, assuming the peer
proposes a closing fee of 3000 satoshi and our estimate shows it must be 4000:

- "10": our next proposal will be 4000-10=3990.
- "10%": our next proposal will be 4000-(10% of (4000-3000))=3900.
- "1": our next proposal will be 3999. This is the most extreme case when we
insist on our fee as much as possible.
- "100%": our next proposal will be 3000. This is the most relaxed case when
we quickly accept the peer's proposal.

The default is "50%".

*wrong\_funding* can only be specified if both sides have offered
the "shutdown\_wrong\_funding" feature (enabled by the
**experimental-shutdown-wrong-funding** option): it must be a
transaction id followed by a colon then the output number.  Instead of
negotiating a shutdown to spend the expected funding transaction, the
shutdown transaction will spend this output instead.  This is only
allowed if this peer opened the channel and the channel is unused: it
can rescue openings which have been manually miscreated.

*force\_lease\_closed* if the channel has funds leased to the peer
(option\_will\_fund), we prevent initiation of a mutual close
unless this flag is passed in. Defaults to false.

*feerange* is an optional array [ *min*, *max* ], indicating the
minimum and maximum feerates to offer: the peer will obey these if it
supports the quick-close protocol.  *slow* and *unilateral\_close* are
the defaults.  See NOTES in lightning-feerates(7) for possible values.

Note that the maximum fee will be capped at the final commitment
transaction fee (unless the experimental anchor-outputs option is
negotiated).

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
