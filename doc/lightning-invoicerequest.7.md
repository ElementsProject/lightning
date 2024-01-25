lightning-invoicerequest -- Command for offering payments
=========================================================

SYNOPSIS
--------

**(WARNING: experimental-offers only)**

**invoicerequest** *amount* *description* [*issuer*] [*label*] [*absolute\_expiry*] [*single\_use*]

DESCRIPTION
-----------

The **invoicerequest** RPC command creates an `invoice_request` to
send payments: it automatically enables the processing of an incoming
invoice, and payment of it.  The reader of the resulting
`invoice_request` can use lightning-sendinvoice(7) to collect their
payment.

The *amount* parameter can be a positive value in millisatoshi
precision; it can be a whole number, or a whole number ending in
*msat* or *sat*, or a number with three decimal places ending in
*sat*, or a number with 1 to 11 decimal places ending in *btc*.

The *description* is a short description of purpose of the payment,
e.g. *ATM withdrawl*. This value is encoded into the resulting
`invoice_request` and is viewable by anyone you expose it to. It must
be UTF-8, and cannot use *\\u* JSON escape codes.

The *issuer* is another (optional) field exposed in the
`invoice_request`, and reflects who is issuing it (i.e. you) if
appropriate.

The *label* field is an internal-use name for the offer, which can
be any UTF-8 string.

The *absolute\_expiry* is optionally the time the offer is valid
until, in seconds since the first day of 1970 UTC.  If not set, the
`invoice_request` remains valid (though it can be deactivated by the
issuer of course).  This is encoded in the `invoice_request`.

*single\_use* (default true) indicates that the `invoice_request` is
only valid once; we may attempt multiple payments, but as soon as one
is successful no more invoices are accepted (i.e. only one person can
take the money).

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **invreq\_id** (hash): the SHA256 hash of all invoice\_request fields less than 160
- **active** (boolean): whether the invoice\_request is currently active (always *true*)
- **single\_use** (boolean): whether the invoice\_request will become inactive after we pay an invoice for it
- **bolt12** (string): the bolt12 string starting with lnr
- **used** (boolean): whether the invoice\_request has already been used (always *false*)
- **label** (string, optional): the label provided when creating the invoice\_request

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, an error is returned and no `invoice_request` is
created. If the lightning process fails before responding, the caller
should use lightning-listinvoicerequests(7) to query whether it was
created or not.

The following error codes may occur:

- -1: Catchall nonspecific error.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoicerequests(7), lightning-disableinvoicerequest(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:5c264c66454c88f9864744218d0095f11cf85f3fcef77a9f9715e7521cf08059)
