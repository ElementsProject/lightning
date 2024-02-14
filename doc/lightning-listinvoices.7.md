lightning-listinvoices -- Command for querying invoice status
=============================================================

SYNOPSIS
--------

**listinvoices** [*label*] [*invstring*] [*payment\_hash*] [*offer\_id*] [*index* [*start*] [*limit*]]

DESCRIPTION
-----------

The **listinvoices** RPC command gets the status of a specific invoice, if it exists, or the status of all invoices if given no argument.

Only one of the query parameters can be used from *label*, *invstring*, *payment\_hash*, or *offer\_id*.

- **label** (one of, optional): A label used a the creation of the invoice to get a specific invoice.:
  - (string)
  - (integer)
- **invstring** (string, optional): The string value to query a specific invoice.
- **payment\_hash** (hex, optional): A payment\_hash of the invoice to get the details of a specific invoice.
- **offer\_id** (string, optional): A local `offer_id` the invoice was issued for a specific invoice details.
- **index** (string, optional) (one of "created", "updated"): If neither *in\_channel* nor *out\_channel* is specified, it controls ordering. The default is `created`. *(added v23.08)*
- **start** (u64, optional): If `index` is specified, `start` may be specified to start from that value, which is generally returned from lightning-wait(7). *(added v23.08)*
- **limit** (u32, optional): If `index` is specified, `limit` can be used to specify the maximum number of entries to return. *(added v23.08)*

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listinvoices#1",
  "method": "listinvoices",
  "params": {
    "label": "xEoCR94SIz6UIRUEkxum",
    "payment_hash": null,
    "invstring": null,
    "offer_id": null,
    "index": null,
    "start": null,
    "limit": null
  }
}
```

RETURN VALUE
------------

On success, an object containing **invoices** is returned. It is an array of objects, where each object contains:

- **label** (string): Unique label supplied at invoice creation.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **status** (string) (one of "unpaid", "paid", "expired"): Whether it's paid, unpaid or unpayable.
- **expires\_at** (u64): UNIX timestamp of when it will become / became unpayable.
- **created\_index** (u64): 1-based index indicating order this invoice was created in. *(added v23.08)*
- **description** (string, optional): Description used in the invoice.
- **amount\_msat** (msat, optional): The amount required to pay this invoice.
- **bolt11** (string, optional): The BOLT11 string (always present unless *bolt12* is).
- **bolt12** (string, optional): The BOLT12 string (always present unless *bolt11* is).
- **local\_offer\_id** (hash, optional): The *id* of our offer which created this invoice (**experimental-offers** only).
- **invreq\_payer\_note** (string, optional): The optional *invreq\_payer\_note* from invoice\_request which created this invoice (**experimental-offers** only).
- **updated\_index** (u64, optional): 1-based index indicating order this invoice was changed (only present if it has changed since creation). *(added v23.08)*

If **status** is "paid":
  - **pay\_index** (u64): Unique incrementing index for this payment.
  - **amount\_received\_msat** (msat): The amount actually received (could be slightly greater than *amount\_msat*, since clients may overpay).
  - **paid\_at** (u64): UNIX timestamp of when it was paid.
  - **payment\_preimage** (secret): Proof of payment.
  - **paid\_outpoint** (object, optional): Outpoint this invoice was paid with. *(added v23.11)*:
    - **txid** (txid): ID of the transaction that paid the invoice. *(added v23.11)*
    - **outnum** (u32): The 0-based output number of the transaction that paid the invoice. *(added v23.11)*

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "invoices": [
    {
      "label": "xEoCR94SIz6UIRUEkxum",
      "bolt11": "lnbcrt110u1pjmr5lzsp5sfjyj3xn7ux592k36hmmt4ax98n6lgct22wvj54yck0upcmep63qpp5qu436g855lr40ftdt7csatk5pdvtdzzfmfqluwtvm0fds95jsadqdpq0pzk7s6j8y69xjt6xe25j5j4g44hsatdxqyjw5qcqp99qxpqysgquwma3zrw4cd8e8j4u9uh4gxukaacckse64kx2l9dqv8rvrysdq5r5dt38t9snqj9u5ar07h2exr4fg56wpudkhkk7gtxlyt72ku5fpqqd4fnlk",
      "payment_hash": "072b1d20f4a7c757a56d5fb10eaed40b58b68849da41fe396cdbd2d81692875a",
      "amount_msat": 11000000,
      "status": "unpaid",
      "description": [
        "XEoCR94SIz6UIRUEkxum."
      ],
      "expires_at": 1706757730,
      "created_index": 1
    }
  ]
}
```

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-waitinvoice(7), lightning-delinvoice(7), lightning-invoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
