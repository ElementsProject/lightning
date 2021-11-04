lightning-createinvoice -- Low-level invoice creation
=====================================================

SYNOPSIS
--------

**createinvoice** *invstring* *label* *preimage*

DESCRIPTION
-----------

The **createinvoice** RPC command signs and saves an invoice into the
database.

The *invstring* parameter is of bolt11 form, but without the final
signature appended.  Minimal sanity checks are done.  (Note: if
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
- **payment_hash** (hex): the hash of the *payment_preimage* which will prove payment (always 64 characters)
- **status** (string): Whether it has been paid, or can no longer be paid (one of "paid", "expired", "unpaid")
- **description** (string): Description extracted from **bolt11** or **bolt12**
- **expires_at** (u64): UNIX timestamp of when invoice expires (or expired)
- **bolt11** (string, optional): the bolt11 string (always present unless **bolt12** is)
- **bolt12** (string, optional): the bolt12 string instead of **bolt11** (**experimental-offers** only)
- **amount_msat** (msat, optional): The amount of the invoice (if it has one)
- **pay_index** (u64, optional): Incrementing id for when this was paid (**status** *paid* only)
- **amount_received_msat** (msat, optional): Amount actually received (**status** *paid* only)
- **paid_at** (u64, optional): UNIX timestamp of when invoice was paid (**status** *paid* only)
- **payment_preimage** (hex, optional): the proof of payment: SHA256 of this **payment_hash** (always 64 characters)
- **local_offer_id** (hex, optional): the *id* of our offer which created this invoice (**experimental-offers** only). (always 64 characters)
- **payer_note** (string, optional): the optional *payer_note* from invoice_request which created this invoice (**experimental-offers** only).

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

[comment]: # ( SHA256STAMP:ea89ed849c8ad6cac8e1e136999046d1f7589bf176be0e65438174357f87ed11)
