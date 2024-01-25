lightning-signinvoice -- Low-level invoice signing
=====================================================

SYNOPSIS
--------

**signinvoice** *invstring*

DESCRIPTION
-----------

The **signinvoice** RPC command signs an invoice.  Unlike
**createinvoice** it does not save the invoice into the database and
thus does not require the preimage.

The *invstring* parameter is of bolt11 form, but the final signature
is ignored.  Minimal sanity checks are done.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **bolt11** (string): the bolt11 string

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, an error is returned.

The following error codes may occur:

- -1: Catchall nonspecific error.

AUTHOR
------

Carl Dong <<contact@carldong.me>> is mainly responsible.

SEE ALSO
--------

lightning-createinvoice(7), lightning-invoice(7), lightning-listinvoices(7),
lightning-delinvoice(7), lightning-getroute(7), lightning-sendpay(7),
lightning-offer(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:5f0154bc5c2e60c7ae5e238cd803a1171552c7c7fa46ddda538cd71ea1511533)
