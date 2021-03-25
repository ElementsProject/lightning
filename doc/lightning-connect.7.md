lightning-connect -- Command for connecting to another lightning node
=====================================================================

SYNOPSIS
--------

**connect** *id* \[*host* *port*\]

DESCRIPTION
-----------

The **connect** RPC command establishes a new connection with another
node in the Lightning Network.

*id* represents the target node’s public key. As a convenience, *id* may
be of the form *id@host* or *id@host:port*. In this case, the *host* and
*port* parameters must be omitted.

*host* is the peer’s hostname or IP address.

If not specified, the *port* defaults to 9735.

If *host* is not specified (or doesn't work), the connection will be attempted to an IP
belonging to *id* obtained through gossip with other already connected
peers.
This can fail if your C-lightning node is a fresh install that has not
connected to any peers yet (your node has no gossip yet),
or if the target *id* is a fresh install that has no channels yet
(nobody will gossip about a node until it has one published channel).

If *host* begins with a */* it is interpreted as a local path, and the
connection will be made to that local socket (see **bind-addr** in
lightningd-config(5)).

Connecting to a node is just the first step in opening a channel with
another node. Once the peer is connected a channel can be opened with
lightning-fundchannel(7).

RETURN VALUE
------------

On success the peer *id* is returned, as well as a hexidecimal
*features* bitmap, a *direction* ("in" if they connected to us, "out"
if we connected to them") and an *address* object as per
lightning-listnodes(7).  Note that *address* will be less useful if 
"direction" is "in", especially if a proxy is in use.

ERRORS
------

On failure, one of the following errors will be returned:

    { "code" : 400, "message" : "Unable to connect, no address known for peer" }

If some addresses are known but connecting to all of them failed, the message
will contain details about the failures:

    { "code" : 401, "message" : "..." }

If the given parameters are wrong:

    { "code" : -32602, "message" : "..." }

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.
Felix <<fixone@gmail.com>> is the original author of this manpage.

SEE ALSO
--------

lightning-fundchannel(7), lightning-listpeers(7),
lightning-listchannels(7), lightning-disconnect(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

