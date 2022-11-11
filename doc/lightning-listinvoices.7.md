lightning-listinvoices -- Command for querying invoice status
=============================================================

SYNOPSIS
--------

**listinvoices** [*label*] [*invstring*] [*payment\_hash*] [*offer\_id*]

DESCRIPTION
-----------

The **listinvoices** RPC command gets the status of a specific invoice,
if it exists, or the status of all invoices if given no argument.

A specific invoice can be queried by providing either the `label`
provided when creating the invoice, the `invstring` string representing
the invoice, the `payment_hash` of the invoice, or the local `offer_id`
this invoice was issued for. Only one of the query parameters can be used at once.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **invoices** is returned.  It is an array of objects, where each object contains:

- **label** (string): unique label supplied at invoice creation
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment (always 64 characters)
- **status** (string): Whether it's paid, unpaid or unpayable (one of "unpaid", "paid", "expired")
- **expires\_at** (u64): UNIX timestamp of when it will become / became unpayable
- **description** (string, optional): description used in the invoice
- **amount\_msat** (msat, optional): the amount required to pay this invoice
- **bolt11** (string, optional): the BOLT11 string (always present unless *bolt12* is)
- **bolt12** (string, optional): the BOLT12 string (always present unless *bolt11* is)
- **local\_offer\_id** (hex, optional): the *id* of our offer which created this invoice (**experimental-offers** only). (always 64 characters)
- **invreq\_payer\_note** (string, optional): the optional *invreq\_payer\_note* from invoice\_request which created this invoice (**experimental-offers** only).

If **status** is "paid":

  - **pay\_index** (u64): Unique incrementing index for this payment
  - **amount\_received\_msat** (msat): the amount actually received (could be slightly greater than *amount\_msat*, since clients may overpay)
  - **paid\_at** (u64): UNIX timestamp of when it was paid
  - **payment\_preimage** (secret): proof of payment (always 64 characters)

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-waitinvoice(7), lightning-delinvoice(7), lightning-invoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:67af32ecf6319aec4376074b0f0a1b42cf111cbb3acec0108d7f3607dc441252)
