lightning-sendinvoice -- Command for send an invoice for an offer
=================================================================

SYNOPSIS
--------

*EXPERIMENTAL_FEATURES only*

**sendinvoice** *offer* \[*label*\] \[*msatoshi*\] \[*timeout*\] \[*invoice_timeout*\] \[*quantity*\]

DESCRIPTION
-----------

The **sendinvoice** RPC command creates and sends an invoice to the
issuer of an *offer* for it to pay: the offer must contain
*send_invoice*; see lightning-fetchinvoice(7).

*offer* is the bolt12 offer string beginning with "lno1".

*label* is the unique label to use for this invoice.

*msatoshi* is optional: it is required if the *offer* does not specify
an amount at all, or specifies it in a different currency.  Otherwise
you may set it (e.g. to provide a tip), and if not it defaults to the
amount contained in the offer (multiplied by *quantity* if any).

*timeout* is how many seconds to wait for the offering node to pay the
invoice or return an error, default 90 seconds.

*invoice_timeout* can be set to greater than *timeout*, to give the
offering node longer to pay; in this case *sendinvoice* will time out
but the invoice will still be valid, and the caller should monitor it.

*quantity* is optional: it is required if the *offer* specifies
*quantity_min* or *quantity_max*, otherwise it is not allowed.

RETURN VALUE
------------

On success, an object as per lightning-waitinvoice(7).

The following error codes may occur:
- -1: Catchall nonspecific error.
- 1002: Offer has expired.
- 1003: Cannot find a route to the node making the offer.
- 1004: The node making the offer returned an error message.
- 1005: We timed out waiting for the invoice to be paid

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-fetchinvoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

