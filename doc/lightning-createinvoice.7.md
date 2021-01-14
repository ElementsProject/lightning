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

On success, an invoice object is returned, as per listinvoices(7).

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
lightning-getroute(7), lightning-sendpay(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

