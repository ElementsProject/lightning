lightning-listinvoices -- Command for querying invoice status
=============================================================

SYNOPSIS
--------

**listinvoices** [*label*] [*invstring*] [*payment_hash*] [*offer_id*]

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
- **description** (string): description used in the invoice
- **payment_hash** (hex): the hash of the *payment_preimage* which will prove payment (always 64 characters)
- **status** (string): Whether it's paid, unpaid or unpayable (one of "unpaid", "paid", "expired")
- **expires_at** (u64): UNIX timestamp of when it will become / became unpayable
- **amount_msat** (msat, optional): the amount required to pay this invoice
- **bolt11** (string, optional): the BOLT11 string (always present unless *bolt12* is)
- **bolt12** (string, optional): the BOLT12 string (always present unless *bolt11* is)
- **local_offer_id** (hex, optional): the *id* of our offer which created this invoice (**experimental-offers** only). (always 64 characters)
- **payer_note** (string, optional): the optional *payer_note* from invoice_request which created this invoice (**experimental-offers** only).

If **status** is "paid":
  - **pay_index** (u64): Unique incrementing index for this payment
  - **amount_received_msat** (msat): the amount actually received (could be slightly greater than *amount_msat*, since clients may overpay)
  - **paid_at** (u64): UNIX timestamp of when it was paid
  - **payment_preimage** (hex): proof of payment (always 64 characters)

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

[comment]: # ( SHA256STAMP:3dc5d5b8f7796d29e0d174d96e93915cbc7131b173a1547de022e021c55e8db6)
