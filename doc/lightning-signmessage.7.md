lightning-signmessage -- Command to create a signature from this node
=====================================================================

SYNOPSIS
--------

**signmessage** *message*

DESCRIPTION
-----------

The **signmessage** RPC command creates a digital signature of
*message* using this node's secret key.  A receiver who knows your
node's *id* and the *message* can be sure that the resulting signature could
only be created by something with access to this node's secret key.

*message* must be less that 65536 characters.

RETURN VALUE
------------
An object with attributes *signature*, *recid* and *zbase* is
returned.  *zbase* is the result of *signature* and *recid* encoded in
a style compatible with **lnd**'s [SignMessageRequest](https://api.lightning.community/#grpc-request-signmessagerequest).

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-checkmessage(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

