lightning-connect -- Command for connecting to another lightning node
=====================================================================

SYNOPSIS
--------

**connect** *id* [*host*] [*port*]

DESCRIPTION
-----------

The **connect** RPC command establishes a new connection with another
node in the Lightning Network.

Connecting to a node is just the first step in opening a channel with
another node. Once the peer is connected a channel can be opened with
lightning-fundchannel(7).

If there are active channels with the peer, **connect** returns once
all the subdaemons are in place to handle the channels, not just once
it's connected.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **id** (pubkey): the peer we connected to
- **features** (hex): BOLT 9 features bitmap offered by peer
- **direction** (string): Whether they initiated connection or we did (one of "in", "out")
- **address** (object): Address information (mainly useful if **direction** is *out*):
  - **type** (string): Type of connection (*torv2*/*torv3* only if **direction** is *out*) (one of "local socket", "ipv4", "ipv6", "torv2", "torv3")

  If **type** is "local socket":

    - **socket** (string): socket filename

  If **type** is "ipv4", "ipv6", "torv2" or "torv3":

    - **address** (string): address in expected format for **type**
    - **port** (u16): port number

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

On failure, one of the following errors will be returned:

    { "code" : 400, "message" : "Unable to connect, no address known for peer" }

If some addresses are known but connecting to all of them failed, the message
will contain details about the failures:

    { "code" : 401, "message" : "..." }

If the peer disconnected while we were connecting:

    { "code" : 402, "message" : "..." }

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

[comment]: # ( SHA256STAMP:fc79236aaca9d4c46a85e73c7f3e5fae92436a86f26e48f6bc53b870e954d769)
