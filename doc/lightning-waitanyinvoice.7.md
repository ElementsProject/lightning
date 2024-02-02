lightning-waitanyinvoice -- Command for waiting for payments
============================================================

SYNOPSIS
--------

**waitanyinvoice** [*lastpay\_index*] [*timeout*]

DESCRIPTION
-----------

The **waitanyinvoice** RPC command waits until an invoice is paid, then
returns a single entry as per **listinvoice**. It will not return for
any invoices paid prior to or including the *lastpay\_index*.

This is usually called iteratively: once with no arguments, then
repeatedly with the returned *pay\_index* entry. This ensures that no
paid invoice is missed. The *pay\_index* is a monotonically-increasing number
assigned to an invoice when it gets paid. The first valid *pay\_index* is 1.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **label** (string): unique label supplied at invoice creation
- **description** (string): description used in the invoice
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **status** (string): Whether it's paid or expired (one of "paid", "expired")
- **expires\_at** (u64): UNIX timestamp of when it will become / became unpayable
- **created\_index** (u64): 1-based index indicating order this invoice was created in *(added v23.08)*
- **amount\_msat** (msat, optional): the amount required to pay this invoice
- **bolt11** (string, optional): the BOLT11 string (always present unless *bolt12* is)
- **bolt12** (string, optional): the BOLT12 string (always present unless *bolt11* is)
- **updated\_index** (u64, optional): 1-based index indicating order this invoice was changed (only present if it has changed since creation) *(added v23.08)*

If **status** is "paid":

  - **pay\_index** (u64): Unique incrementing index for this payment
  - **amount\_received\_msat** (msat): the amount actually received (could be slightly greater than *amount\_msat*, since clients may overpay)
  - **paid\_at** (u64): UNIX timestamp of when it was paid
  - **payment\_preimage** (secret): proof of payment
  - **paid\_outpoint** (object, optional): Outpoint this invoice was paid with *(added v23.11)*:
    - **txid** (txid): ID of the transaction that paid the invoice *(added v23.11)*
    - **outnum** (u32): The 0-based output number of the transaction that paid the invoice *(added v23.11)*

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The following error codes may occur:

- 904: The *timeout* was reached without an invoice being paid.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-waitinvoice(7), lightning-listinvoice(7),
lightning-delinvoice(7), lightning-invoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:9e15a21311e8822a4e61a2f47f047caea6a8fa2a65acd1c81854c0c42ea6bba1)
