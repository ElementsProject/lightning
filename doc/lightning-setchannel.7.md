lightning-setchannel -- Command for configuring fees / htlc range advertized for a channel
===========================================================================================

SYNOPSIS
--------

**setchannel** *id* [*feebase*] [*feeppm*] [*htlcmin*] [*htlcmax*] [*enforcedelay*]

DESCRIPTION
-----------

The **setchannel** RPC command sets channel specific routing fees, and
`htlc_minimum_msat` or `htlc_maximum_msat` as defined in BOLT \#7. The channel has to be in
normal or awaiting state.  This can be checked by **listpeers**
reporting a *state* of CHANNELD\_NORMAL or CHANNELD\_AWAITING\_LOCKIN
for the channel.

These changes (for a public channel) will be broadcast to the rest of
the network (though many nodes limit the rate of such changes they
will accept: we allow 2 a day, with a few extra occasionally).

*id* is required and should contain a scid (short channel ID), channel
id or peerid (pubkey) of the channel to be modified. If *id* is set to
"all", the updates are applied to all channels in states
CHANNELD\_NORMAL CHANNELD\_AWAITING\_LOCKIN or DUALOPEND_AWAITING_LOCKIN.
If *id* is a peerid, all channels with the +peer in those states are
changed.

*feebase* is an optional value in millisatoshi that is added as base fee to
any routed payment: if omitted, it is unchanged.  It can be a whole number, or a whole
number ending in *msat* or *sat*, or a number with three decimal places
ending in *sat*, or a number with 1 to 11 decimal places ending in
*btc*.

*feeppm* is an optional value that is added proportionally per-millionths
to any routed payment volume in satoshi. For example, if ppm is 1,000
and 1,000,000 satoshi is being routed through the channel, an
proportional fee of 1,000 satoshi is added, resulting in a 0.1% fee.

*htlcmin* is an optional value that limits how small an HTLC we will
send: if omitted, it is unchanged (the default is no lower limit). It
can be a whole number, or a whole number ending in *msat* or *sat*, or
a number with three decimal places ending in *sat*, or a number with 1
to 11 decimal places ending in *btc*.  The peer also enforces a
minimum for the channel: setting it below will be ignored.

*htlcmax* is an optional value that limits how large an HTLC we will
send: if omitted, it is unchanged (the default is no effective
limit). It can be a whole number, or a whole number ending in *msat*
or *sat*, or a number with three decimal places ending in *sat*, or a
number with 1 to 11 decimal places ending in *btc*.

*enforcedelay* is the number of seconds to delay before enforcing the
new fees/htlc max (default 600, which is ten minutes).  This gives the
network a chance to catch up with the new rates and avoids rejecting
HTLCs before they do.  This only has an effect if rates are increased
(we always allow users to overpay fees) or *htlcmax* is decreased, and
only applied to a single rate increase per channel (we don't remember
an arbitrary number of prior feerates) and if the node is restarted
the updated configuration is enforced immediately.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **channels** is returned.  It is an array of objects, where each object contains:
- **peer_id** (pubkey): The node_id of the peer
- **channel_id** (hex): The channel_id of the channel (always 64 characters)
- **fee_base_msat** (msat): The resulting feebase (this is the BOLT #7 name)
- **fee_proportional_millionths** (u32): The resulting feeppm (this is the BOLT #7 name)
- **minimum_htlc_out_msat** (msat): The resulting htlcmin we will advertize (the BOLT #7 name is htlc_minimum_msat)
- **maximum_htlc_out_msat** (msat): The resulting htlcmax we will advertize (the BOLT #7 name is htlc_maximum_msat)
- **short_channel_id** (short_channel_id, optional): the short_channel_id (if locked in)
- the following warnings are possible:
  - **warning_htlcmin_too_low**: The requested htlcmin was too low for this peer, so we set it to the minimum they will allow
  - **warning_htlcmax_too_high**: The requested htlcmax was greater than the channel capacity, so we set it to the channel capacity

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The following error codes may occur:
- -1: Channel is in incorrect state, i.e. Catchall nonspecific error.
- -32602: JSONRPC2\_INVALID\_PARAMS, i.e. Given id is not a channel ID
or short channel ID.

AUTHOR
------

Michael Schmoock <<michael@schmoock.net>> is the author of this
feature. Rusty Russell <<rusty@rustcorp.com.au>> is mainly
responsible for the Core Lightning project.

SEE ALSO
--------

lightningd-config(5), lightning-fundchannel(7),
lightning-listchannels(7), lightning-listpeers(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:a38b5ea12566d9e40eab07b95a90007bf66373ac1189f458d1678634522575b3)
