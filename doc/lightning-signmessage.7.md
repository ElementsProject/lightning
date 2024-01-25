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
[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **signature** (hex): The signature (always 128 characters)
- **recid** (hex): The recovery id (0, 1, 2 or 3) (always 2 characters)
- **zbase** (string): *signature* and *recid* encoded in a style compatible with **lnd**'s [SignMessageRequest](https://api.lightning.community/#grpc-request-signmessagerequest)

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-checkmessage(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:485db85e3822babcb397b55f251e6797528c3b9e14743d2823e890e2b22432c0)
