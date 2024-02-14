lightning-sendonionmessage -- low-level command to send an onion message
========================================================================

SYNOPSIS
--------

**(WARNING: experimental-onion-messages only)**

**sendonionmessage** *first\_id* *blinding* *hops* 

DESCRIPTION
-----------

The **sendonionmessage** RPC command can be used to send a message via the lightning network. These are currently used by *offers* to request and receive invoices.

- **first\_id** (pubkey): The (presumably well-known) public key of the start of the path.
- **blinding** (pubkey): Blinding factor for this path.
- **hops** (array of objects): 
 :
  - **node** (pubkey): Public key of the node.
  - **tlv** (u8): Contains a hexadecimal TLV to include.

RETURN VALUE
------------

On success, an empty object is returned.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-fetchinvoice(7), lightning-offer(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[bolt04]: https://github.com/lightning/bolts/blob/master/04-onion-routing.md
