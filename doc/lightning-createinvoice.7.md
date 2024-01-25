lightning-createinvoice -- Low-level invoice creation
=====================================================

SYNOPSIS
--------

**createinvoice** *invstring* *label* *preimage*

DESCRIPTION
-----------

The **createinvoice** RPC command signs and saves an invoice into the
database.

The *invstring* parameter is of bolt11 form, but the final signature
is ignored.  Minimal sanity checks are done.  (Note: if
**experimental-offers** is enabled, *invstring* can actually be an
unsigned bolt12 invoice).

The *label* must be a unique string or number (which is treated as a
string, so "01" is different from "1"); it is never revealed to other
nodes on the lightning network, but it can be used to query the status
of this invoice.

The *preimage* is the preimage to supply upon successful payment of
the invoice.

RETURN VALUE
------------

(Note: the return format is the same as lightning-listinvoices(7)).

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **label** (string): the label for the invoice
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **status** (string): Whether it has been paid, or can no longer be paid (one of "paid", "expired", "unpaid")
- **description** (string): Description extracted from **bolt11** or **bolt12**
- **expires\_at** (u64): UNIX timestamp of when invoice expires (or expired)
- **created\_index** (u64): 1-based index indicating order this invoice was created in *(added v23.08)*
- **bolt11** (string, optional): the bolt11 string (always present unless **bolt12** is)
- **bolt12** (string, optional): the bolt12 string instead of **bolt11** (**experimental-offers** only)
- **amount\_msat** (msat, optional): The amount of the invoice (if it has one)
- **pay\_index** (u64, optional): Incrementing id for when this was paid (**status** *paid* only)
- **amount\_received\_msat** (msat, optional): Amount actually received (**status** *paid* only)
- **paid\_at** (u64, optional): UNIX timestamp of when invoice was paid (**status** *paid* only)
- **paid\_outpoint** (object, optional): Outpoint this invoice was paid with (**status** *paid* only) *(added v23.11)*:
  - **txid** (txid): ID of the transaction that paid the invoice (**status** *paid* only) *(added v23.11)*
  - **outnum** (u32): The 0-based output number of the transaction that paid the invoice (**status** *paid* only) *(added v23.11)*
- **payment\_preimage** (secret, optional): the proof of payment: SHA256 of this **payment\_hash**
- **local\_offer\_id** (hex, optional): the *id* of our offer which created this invoice (**experimental-offers** only). (always 64 characters)
- **invreq\_payer\_note** (string, optional): the optional *invreq\_payer\_note* from invoice\_request which created this invoice (**experimental-offers** only).

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, an error is returned and no invoice is created. If the
lightning process fails before responding, the caller should use
lightning-listinvoices(7) to query whether this invoice was created or
not.

The following error codes may occur:

- -1: Catchall nonspecific error.
- 900: An invoice with the given *label* already exists.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-invoice(7), lightning-listinvoices(7), lightning-delinvoice(7),
lightning-getroute(7), lightning-sendpay(7), lightning-offer(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:ad1c985a529da5c845c1d6d348556e61531a6ec75e9a47dc91e9a276008d3ffa)
