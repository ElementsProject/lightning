lightning-waitanyinvoice -- Command for waiting for payments
============================================================

SYNOPSIS
--------

**waitanyinvoice** [*lastpay\_index*] [*timeout*] 

DESCRIPTION
-----------

The **waitanyinvoice** RPC command waits until an invoice is paid, then returns a single entry as per **listinvoice**. It will not return for any invoices paid prior to or including the *lastpay\_index*.

This is usually called iteratively: once with no arguments, then repeatedly with the returned *pay\_index* entry. This ensures that no paid invoice is missed. The *pay\_index* is a monotonically-increasing number assigned to an invoice when it gets paid. The first valid *pay\_index* is 1.

- **lastpay\_index** (u64, optional): Ignores any invoices paid prior to or including this index. 0 is equivalent to not specifying and negative value is invalid.
- **timeout** (u64, optional): If specified, wait at most that number of seconds, which must be an integer. If the specified *timeout* is reached, this command will return with an error. You can specify this to 0 so that **waitanyinvoice** will return immediately with an error if no pending invoice is available yet. If unspecified, this command will wait indefinitely.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:waitanyinvoice#1",
  "method": "waitanyinvoice",
  "params": {
    "lastpay_index": null,
    "timeout": null
  }
}
{
  "id": "example:waitanyinvoice#2",
  "method": "waitanyinvoice",
  "params": {
    "lastpay_index": 3,
    "timeout": 0
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **label** (string): Unique label supplied at invoice creation.
- **description** (string): Description used in the invoice.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **status** (string) (one of "paid", "expired"): Whether it's paid or expired.
- **expires\_at** (u64): UNIX timestamp of when it will become / became unpayable.
- **created\_index** (u64): 1-based index indicating order this invoice was created in. *(added v23.08)*
- **amount\_msat** (msat, optional): The amount required to pay this invoice.
- **bolt11** (string, optional): The BOLT11 string (always present unless *bolt12* is).
- **bolt12** (string, optional): The BOLT12 string (always present unless *bolt11* is).
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
  "label": "inv1",
  "bolt11": "lnbcrt10n1pjmxtsxsp56sn02x8lccjfsvunnhz5858zuyxztug9luy226w4qsmfm4r8pkcspp5gw5r0dw99yf3zqxrg24l8g9m9hun9cu06ldg4rga8s9t9kv8z45sdq8d9h8vvgxqyjw5qcqp99qxpqysgqv537uh2sx8ch640mf4t43t8qjtpg3z7gukgm07tlyq986m7nvsnxkapg37z4vsxtl4thfqzc64anqr83geygkc2xaftxgr97dltqfjqpe3mhja",
  "payment_hash": "43a837b5c529131100c342abf3a0bb2df932e38fd7da8a8d1d3c0ab2d9871569",
  "amount_msat": 1000,
  "status": "paid",
  "pay_index": 1,
  "amount_received_msat": 1000,
  "paid_at": 1706241546,
  "payment_preimage": "a0c668998de14b975f33e1060b3efd7efc0bde784ac266ab667a1b2fddab3cd1",
  "description": [
    "Inv1."
  ],
  "expires_at": 1706846342,
  "created_index": 1,
  "updated_index": 1
}
{
  "label": "inv4",
  "bolt11": "lnbcrt10n1pja0tkmsp57j4z9zwvdsyh57unh3da7aac5z20clfnrwy5nqm6wujaelduw23qpp580mdrwakz9xewc2vhvpucset9gjkgdvyhw7h9frcy2d6p2lwdw2qdq8d9h8vdqxqyjw5qcqp99qxpqysgqtgyzhtxs3p2dyk8wk9q028033303702d2hml4frmu38qe79mrkgzgxvyjmq2q4nhjgcuz3uhmlda3jnhf9w6mj8mj97pkgnda9l5kdcqsdgewf",
  "payment_hash": "3bf6d1bbb6114d97614cbb03cc432b2a25643584bbbd72a478229ba0abee6b94",
  "amount_msat": 1000,
  "status": "paid",
  "pay_index": 4,
  "amount_received_msat": 1000,
  "paid_at": 1708633825,
  "payment_preimage": "77336a342dde76050c7ee7fc18599e407dfc1edad3c784ba68e9603004365b94",
  "description": "inv4",
  "expires_at": 1709238619,
  "created_index": 4,
  "updated_index": 4
}
```

ERRORS
------

The following error codes may occur:

- 904: The *timeout* was reached without an invoice being paid.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-waitinvoice(7), lightning-listinvoice(7), lightning-delinvoice(7), lightning-invoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
