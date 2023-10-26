lightning-listinvoices -- Command for querying invoice status
=============================================================

SYNOPSIS
--------

**listinvoices** [*label*] [*invstring*] [*payment\_hash*] [*offer\_id*] [*index* [*start*] [*limit*]]

DESCRIPTION
-----------

The **listinvoices** RPC command gets the status of a specific invoice,
if it exists, or the status of all invoices if given no argument.

A specific invoice can be queried by providing either the `label`
provided when creating the invoice, the `invstring` string representing
the invoice, the `payment_hash` of the invoice, or the local `offer_id`
this invoice was issued for. Only one of the query parameters can be used at once.

`index` controls ordering, by `created` (default) or `updated`.  If
`index` is specified, `start` may be specified to start from that
value, which is generally returned from lightning-wait(7), and `limit`
can be used to specify the maximum number of entries to return.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **invoices** is returned.  It is an array of objects, where each object contains:

- **label** (string): unique label supplied at invoice creation
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **status** (string): Whether it's paid, unpaid or unpayable (one of "unpaid", "paid", "expired")
- **expires\_at** (u64): UNIX timestamp of when it will become / became unpayable
- **created\_index** (u64): 1-based index indicating order this invoice was created in *(added v23.08)*
- **description** (string, optional): description used in the invoice
- **amount\_msat** (msat, optional): the amount required to pay this invoice
- **bolt11** (string, optional): the BOLT11 string (always present unless *bolt12* is)
- **bolt12** (string, optional): the BOLT12 string (always present unless *bolt11* is)
- **local\_offer\_id** (hash, optional): the *id* of our offer which created this invoice (**experimental-offers** only).
- **invreq\_payer\_note** (string, optional): the optional *invreq\_payer\_note* from invoice\_request which created this invoice (**experimental-offers** only).
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

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-waitinvoice(7), lightning-delinvoice(7), lightning-invoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:7e4b1182ba879bea892d143b53cdc31350a9668c734c6bb8f86ab9b6e3f0b06e)
