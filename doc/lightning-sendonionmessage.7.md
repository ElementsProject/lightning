lightning-sendonionmessage -- low-level command to send an onion message
================================================================

SYNOPSIS
--------

**(WARNING: experimental-onion-messages only)**

**sendonionmessage** *first_id* *blinding* *hops*

DESCRIPTION
-----------

The **sendonionmessage** RPC command can be used to send a message via
the lightning network.  These are currently used by *offers* to request
and receive invoices.

*hops* is an array of json objects: *id* as a public key of the node,
and *tlv* contains a hexidecimal TLV to include.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an empty object is returned.

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-fetchinvoice(7), lightning-offer(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[bolt04]: https://github.com/lightning/bolts/blob/master/04-onion-routing.md

[comment]: # ( SHA256STAMP:200de829c6635242cb2dd8ec0650c2fa8f5fcbf413f4a704884516df80492fcb)
