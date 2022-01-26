lightning-sendonionmessage -- low-level command to send an onion message
================================================================

SYNOPSIS
--------

**(WARNING: experimental-onion-messages only)**

**sendonionmessage** *hops* [*reply_path*]

DESCRIPTION
-----------

The **sendonionmessage** RPC command can be used to send a message via
the lightning network.  These are currently used by *offers* to request
and receive invoices.

*hops* is an array of json objects: *id* as a public key of the node,
and either *rawtlv* containing a hexidecimal TLV to include, or any of
the fields *short_channel_id*, *blinding*, *enctlv*, *invoice*,
*invoice_request* and *invoice_error* to construct the onionmessage
TLV with.

*reply_path* is a json object, containing a pubkey *blinding*, and an
array *path* of objects containing *id* (a pubkey) and *enctlv* (a hex
value, optional for final element).

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

[bolt04]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md

[comment]: # ( SHA256STAMP:39a66bd8e28db8780d7b1365372f7cc638b32a80bb5515657d381b4520f06901)
