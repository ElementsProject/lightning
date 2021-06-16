lightning-listinvoices -- Command for querying invoice status
=============================================================

SYNOPSIS
--------

**listinvoices** \[*label*\] \[*invstring*\] \[*payment_hash*\]

DESCRIPTION
-----------

The **listinvoices** RPC command gets the status of a specific invoice,
if it exists, or the status of all invoices if given no argument.

A specific invoice can be queried by providing either the `label`
provided when creating the invoice, the `invstring` string representing
the invoice, or the `payment_hash` of the invoice. Only one of the
query parameters can be used at once.

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

[comment]: # ( SHA256STAMP:67ff5d9aa945301f23d6694304e4b657a37f0b3f80cc1c13c2ff23a55fe51d4b)
