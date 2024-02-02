lightning-setchannel -- Command for configuring fees / htlc range advertized for a channel
===========================================================================================

SYNOPSIS
--------

**setchannel** *id* [*feebase*] [*feeppm*] [*htlcmin*] [*htlcmax*] [*enforcedelay*] [*ignorefeelimits*]

DESCRIPTION
-----------

The **setchannel** RPC command sets channel specific routing fees, and
`htlc_minimum_msat` or `htlc_maximum_msat` as defined in BOLT \#7. The channel has to be in
normal or awaiting state. This can be checked by **listpeers**
reporting a *state* of CHANNELD\_NORMAL or CHANNELD\_AWAITING\_LOCKIN
for the channel.

These changes (for a public channel) will be broadcast to the rest of
the network (though many nodes limit the rate of such changes they
will accept: we allow 2 a day, with a few extra occasionally).

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

[comment]: # ( SHA256STAMP:b9516a162d2448b85ca9628fdf965c037eb5947f5fed827ddc674ba7c283e9f0)
