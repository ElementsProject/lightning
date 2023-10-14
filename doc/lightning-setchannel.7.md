lightning-setchannel -- Command for configuring fees / htlc range advertized for a channel
===========================================================================================

SYNOPSIS
--------

**setchannel** *id* [*feebase*] [*feeppm*] [*htlcmin*] [*htlcmax*] [*enforcedelay*] [*ignorefeelimits*]

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
CHANNELD\_NORMAL CHANNELD\_AWAITING\_LOCKIN or DUALOPEND\_AWAITING\_LOCKIN.
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
forward: if omitted, it is unchanged (the default is no lower limit). It
can be a whole number, or a whole number ending in *msat* or *sat*, or
a number with three decimal places ending in *sat*, or a number with 1
to 11 decimal places ending in *btc*.  Note that the peer also enforces a
minimum for the channel: setting it below that will simply set it to
that value with a warning.  Also note that *htlcmin* only applies to forwarded
HTLCs: we can still send smaller payments ourselves.

*htlcmax* is an optional value that limits how large an HTLC we will
forward: if omitted, it is unchanged (the default is no effective
limit). It can be a whole number, or a whole number ending in *msat*
or *sat*, or a number with three decimal places ending in *sat*, or a
number with 1 to 11 decimal places ending in *btc*.  Note that *htlcmax*
only applies to forwarded HTLCs: we can still send larger payments ourselves.

*enforcedelay* is the number of seconds to delay before enforcing the
new fees/htlc max (default 600, which is ten minutes).  This gives the
network a chance to catch up with the new rates and avoids rejecting
HTLCs before they do.  This only has an effect if rates are increased
(we always allow users to overpay fees) or *htlcmax* is decreased, and
only applied to a single rate increase per channel (we don't remember
an arbitrary number of prior feerates) and if the node is restarted
the updated configuration is enforced immediately.

*ignorefeelimits* set to True means to allow the peer to set the commitment
transaction fees (or closing transaction fees) to any value they want.  This is dangerous: they could
set an exorbitant fee (so HTLCs are unenforcable), or a tiny fee (so that
commitment transactions cannot be relayed), but avoids channel breakage
in case of feerate disagreements.  (Note: the global `ignore_fee_limits`
setting overrides this).

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **channels** is returned.  It is an array of objects, where each object contains:

- **peer\_id** (pubkey): The node\_id of the peer
- **channel\_id** (hex): The channel\_id of the channel (always 64 characters)
- **fee\_base\_msat** (msat): The resulting feebase (this is the BOLT #7 name)
- **fee\_proportional\_millionths** (u32): The resulting feeppm (this is the BOLT #7 name)
- **ignore\_fee\_limits** (boolean): If we are now allowing peer to set feerate on commitment transaction without restriction *(added v23.08)*
- **minimum\_htlc\_out\_msat** (msat): The resulting htlcmin we will advertize (the BOLT #7 name is htlc\_minimum\_msat)
- **maximum\_htlc\_out\_msat** (msat): The resulting htlcmax we will advertize (the BOLT #7 name is htlc\_maximum\_msat)
- **short\_channel\_id** (short\_channel\_id, optional): the short\_channel\_id (if locked in)
- the following warnings are possible:
  - **warning\_htlcmin\_too\_low**: The requested htlcmin was too low for this peer, so we set it to the minimum they will allow
  - **warning\_htlcmax\_too\_high**: The requested htlcmax was greater than the channel capacity, so we set it to the channel capacity

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

[comment]: # ( SHA256STAMP:5209ba4d4bbe2d897d9824f95a97fa48d968e83ffec2e4cfbd87df6fd90c48f0)
