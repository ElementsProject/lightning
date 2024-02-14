lightning-waitinvoice -- Command for waiting for specific payment
=================================================================

SYNOPSIS
--------

**waitinvoice** *label* 

DESCRIPTION
-----------

The **waitinvoice** RPC command waits until a specific invoice is paid, then returns that single entry as per **listinvoice**.

- **label** (one of): Unique label of the invoice waiting to be paid.:
  - (string)
  - (integer)

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:waitinvoice#1",
  "method": "waitinvoice",
  "params": {
    "label": "inv2"
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
  "label": "inv2",
  "bolt11": "lnbcrt10n1pjmxtwjsp5mzvdu6v8hqsf2tlj0nlyks23afqp7ejs444syjxf74p60ztmld8qpp5q4ayz5pys3t0yj0dmkmh7ctarkv9z434paz4u9rdwnj4f43thhaqdq8d9h8vvsxqyjw5qcqp99qxpqysgqn0055ttns6pafsxh6xuqce6e4vz8gtxlzqx0l9d9f5crmqx4jymh4zy9jdaszm0dj89sq39fvhpwcs626dt0n3gw8kassfdehp5sy3sq7fzy3w",
  "payment_hash": "057a4150248456f249edddb77f617d1d985156350f455e146d74e554d62bbdfa",
  "amount_msat": 1000,
  "status": "paid",
  "pay_index": 1,
  "amount_received_msat": 1000,
  "paid_at": 1706241494,
  "payment_preimage": "34ccd37cc85e067cb376f9ea8c70d70469f58bf296f2566ed9ad4dfb70971a26",
  "description": [
    "Inv2."
  ],
  "expires_at": 1706846290,
  "created_index": 2,
  "updated_index": 1
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: If the invoice is deleted while unpaid, or the invoice does not exist.
- 903: If the invoice expires before being paid, or is already expired.

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-waitanyinvoice(7), lightning-listinvoice(7), lightning-delinvoice(7), lightning-invoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
