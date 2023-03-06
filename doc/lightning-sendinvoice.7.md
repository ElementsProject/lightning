lightning-sendinvoice -- Command for send an invoice for an offer
=================================================================

SYNOPSIS
--------

**(WARNING: experimental-offers only)**

**sendinvoice** *invreq* *label* [*amount\_msat*] [*timeout*] [*quantity*]

DESCRIPTION
-----------

The **sendinvoice** RPC command creates and sends an invoice to the
issuer of an *invoice\_request* for it to pay: lightning-invoicerequest(7).

If **fetchinvoice-noconnect** is not specified in the configuation, it
will connect to the destination in the (currently common!) case where it
cannot find a route which supports `option_onion_messages`.

*invreq* is the bolt12 invoice\_request string beginning with "lnr1".

*label* is the unique label to use for this invoice.

*amount\_msat* is optional: it is required if the *offer* does not specify
an amount at all, or specifies it in a different currency.  Otherwise
you may set it (e.g. to provide a tip), and if not it defaults to the
amount contained in the offer (multiplied by *quantity* if any).

*timeout* is how many seconds to wait for the offering node to pay the
invoice or return an error, default 90 seconds.  This will also be the
timeout on the invoice that is sent.

*quantity* is optional: it is required if the *offer* specifies
*quantity\_max*, otherwise it is not allowed.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **label** (string): unique label supplied at invoice creation
- **description** (string): description used in the invoice
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **status** (string): Whether it's paid, unpaid or unpayable (one of "unpaid", "paid", "expired")
- **expires\_at** (u64): UNIX timestamp of when it will become / became unpayable
- **amount\_msat** (msat, optional): the amount required to pay this invoice
- **bolt12** (string, optional): the BOLT12 string

If **status** is "paid":

  - **pay\_index** (u64): Unique incrementing index for this payment
  - **amount\_received\_msat** (msat): the amount actually received (could be slightly greater than *amount\_msat*, since clients may overpay)
  - **paid\_at** (u64): UNIX timestamp of when it was paid
  - **payment\_preimage** (secret): proof of payment

[comment]: # (GENERATE-FROM-SCHEMA-END)

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

[comment]: # ( SHA256STAMP:79a371e3dc60c1395f591e16c3dd039f8fdee53c9402f345fa8823d85a18d819)
