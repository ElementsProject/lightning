lightning-listchannels -- Command to query active lightning channels in the entire network
==========================================================================================

SYNOPSIS
--------

**listchannels** \[*short\_channel\_id*\] \[*source*\]

DESCRIPTION
-----------

The **listchannels** RPC command returns data on channels that are known
to the node. Because channels may be bidirectional, up to 2 objects will
be returned for each channel (one for each direction).

If *short\_channel\_id* is a short channel id, then only known channels with a
matching *short\_channel\_id* are returned.  Otherwise, it must be null.

If *source* is a node id, then only channels leading from that node id
are returned.

If neither is supplied, data on all lightning channels known to this
node, are returned. These can be local channels or public channels
broadcast on the gossip network.

RETURN VALUE
------------

On success, an object with a "channels" key is returned containing a
list of 0 or more objects.

Each object in the list contains the following data:
- *source* : The node providing entry to the channel, specifying the
fees charged for using the channel in that direction.
- *destination* : The node providing the exit point for the channel.
- *short\_channel\_id* : The channel identifier.
- *public* : Boolean value, is publicly available. Non-local channels
will only ever have this value set to true. Local channels are
side-loaded by this node, rather than obtained through the gossip
network, and so may have this value set to false.
- *satoshis* : Funds available in the channel.
- *amount\_sat* : Same as above, but ending in *sat*.
- *message\_flags* : Bitfield showing the presence of optional fields
in the *channel\_update* message (BOLT \#7).
- *channel\_flags* : Bitfields indicating the direction of the channel
and signaling various options concerning the channel. (BOLT \#7).
- *active* : Boolean value, is available for routing. This is linked
to the channel flags data, where if the second bit is set, signals a
channels temporary unavailability (due to loss of connectivity) OR
permanent unavailability where the channel has been closed but not
settlement on-chain.
- *last\_update* : Unix timestamp (seconds) showing when the last
channel\_update message was received.
- *base\_fee\_millisatoshi* : The base fee (in millisatoshi) charged
for the HTLC (BOLT \#7; equivalent to `fee_base_msat`).
- *fee\_per\_millionth* : The amount (in millionths of a satoshi)
charged per transferred satoshi (BOLT \#7; equivalent to
`fee_proportional_millionths`).
- *delay* : The number of blocks of additional delay required when
forwarding an HTLC in this direction. (BOLT \#7; equivalent to
`cltv_expiry_delta`).
- *htlc\_minimum\_msat* : The minimum payment which can be sent
through this channel.
- *htlc\_maximum\_msat* : The maximum payment which can be sent
through this channel.

If *short\_channel\_id* or *source* is supplied and no matching channels
are found, a "channels" object with an empty list is returned.

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.

AUTHOR
------

Michael Hawkins <<michael.hawkins@protonmail.com>>.

SEE ALSO
--------

lightning-fundchannel(7), lightning-listnodes(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

Lightning RFC site

-   BOLT \#7:
    <https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md>

