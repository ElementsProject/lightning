Frequently Asked Questions
**************************

My channel is stuck in state `x`, what can I do?
================================================

That depends very much on the state that the channel is in, but in
most cases it should resolve itself after a while. Here's a list of
states, their meaning and how long you can expect a channel to be in
this state:

 - ``CHANNELD_AWAITING_LOCKIN``: both endpoints of the channel have
   cooperated to create a funding transaction and we are now waiting
   for the channel to confirm. This usually takes 2 - 6 confirmations,
   i.e., 1 hour on expectation, longer when there are many
   transactions waiting to be confirmed. Both endpoints need to be
   connected to progress from this state so they can exchange the
   ``funding_locked`` message. If you lose connection just ``connect``
   again. If the peer cannot be contacted again you can use ``dev-fail``
   to unilaterally close the channel and recover funds.

 - ``ONCHAIND_THEIR_UNILATERAL``: the other endpoint decided to
   unilaterally close the channel. This can happen for a variety of
   reasons: either side wasn't reachable anymore, the endpoints are
   out of sync, or reconnection failed. This state will return your
   funds to you immediately, but the channel may be in this state for
   a long time until the timeouts for any ongoing payment clear. If
   there are payments that were being negotiated this can take
   approximately 150 confirmations, i.e., over a day. The exact time
   depends on the parameters chosen when establishing the channel and
   are likely overly protective, but better safe than sorry. No
   further action is required to eventually clear the channel.

 - ``ONCHAIND_OUR_UNILATERAL``: this is the counterpart of the previous
   state. It means that your client decided to close the channel, due
   to a timeout or because a reconnection failed. The channel will be
   in this state until the unilateral close timeout expires (144
   blocks by default), plus an eventual HTLC timeout should a payment
   have been interrupted. There is no intervention needed at this
   point, just wait for it to settle.


If for any reason the channels are still stuck in a state after
several days you can use the following procedure to close and forget
the channel:

 - First of all make sure to be running the latest version: pull the
   latest ``master`` commit and recompile the binary. Then restart the
   daemon and wait for it to startup.
 - Check that the channel was confirmed in the first place: use
   ``listpeers [peerid]`` to retrieve the funding transaction ID. Look
   up the funding transaction ID on a block explorer (or your own
   ``bitcoind`` instance) to see if that transaction ever made it to the
   blockchain and was confirmed. If it was not confirmed, use
   ``dev-rescan-outputs`` to get the funding transactions inputs back
   and use ``dev-forget-channel [peerid]`` to remove the channel from
   the channel from your daemon (this should no longer be necessary
   since the issue that was causing this was patched).
 - If the channel was confirmed, make sure you are connected to the
   peer. Use ``listpeers [peerid]`` to check that its ``connected`` field
   is ``true``. If not, try ``connect [peerid] [host] [port]`` to
   reconnect.
 - If the channel is in ``CLOSINGD_SIGEXCHANGE`` for a long time, and
   the peer not connected you can unilaterally close the channel using
   ``dev-fail [peerid]``, this will put you in ``ONCHAIND_OUT_UNILATERAL``
   which will take a day to clear by default.

Why can't I open a new channel to one of my peers?
==================================================

c-lightning currently only supports a single active channel per
peer. That means that if there is an existing channel with the peer in
state ``OPENINGD``, ``CHANNELD_AWAITING_LOCKIN``, ``CHANNELD_NORMAL``,
``ONCHAIND_THEIR_UNILATERAL``, ``ONCHAIND_OUR_UNILATERAL``, or
``CLOSINGD_SIGEXCHANGE``, you will not be able to opena new channel
with that peer. The good news though is that, since lightning has
multihop payments, you can open a channel with someone else, and you
will still be able to route to that peer.
