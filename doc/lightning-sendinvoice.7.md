lightning-sendinvoice -- Command for send an invoice for an offer
=================================================================

SYNOPSIS
--------

**(WARNING: experimental-offers only)**

**sendinvoice** *invreq* *label* [*amount\_msat*] [*timeout*] [*quantity*] 

DESCRIPTION
-----------

The **sendinvoice** RPC command creates and sends an invoice to the issuer of an *invoice\_request* for it to pay: lightning-invoicerequest(7).

If **fetchinvoice-noconnect** is not specified in the configuation, it will connect to the destination in the (currently common!) case where it cannot find a route which supports `option_onion_messages`.

- **invreq** (string): The bolt12 invoice\_request string beginning with `lnr1`.
- **label** (one of): The unique label to use for this invoice.:
  - (string)
  - (integer)
- **amount\_msat** (msat, optional): Required if the *offer* does not specify an amount at all, or specifies it in a different currency. Otherwise you may set it (e.g. to provide a tip). The default is the amount contained in the offer (multiplied by *quantity* if any).
- **timeout** (u32, optional): Seconds to wait for the offering node to pay the invoice or return an error. This will also be the timeout on the invoice that is sent. The default is 90 seconds.
- **quantity** (u64, optional): Quantity is is required if the offer specifies quantity\_max, otherwise it is not allowed.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:sendinvoice#1",
  "method": "sendinvoice",
  "params": {
    "invreq": "lnr1qqg804wzdsyn8g4mf2yc22k8xvjpjzstwd5k6urvv5s8getnw3gzqp3zderpzxstt8927ynqg044h0egcd8n5h3n9g0u0v4h8ncc3yg02gqsykppqgkjyd3q5dv6gllh77kygly9c3kfy0d9xwyjyxsq2nq3c83u5vw4nuzqw5w7y7xqm2rushk5a5n3mcuvqel954raykd5nqa830nq9hpd4s4fcnxw266vp9d5c8f3m3w40hmm6gm8akxx3rsnr7d4usunv0x3q8q",
    "label": "payme for real!"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **label** (string): Unique label supplied at invoice creation.
- **description** (string): Description used in the invoice.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **status** (string) (one of "unpaid", "paid", "expired"): Whether it's paid, unpaid or unpayable.
- **expires\_at** (u64): UNIX timestamp of when it will become / became unpayable.
- **created\_index** (u64): 1-based index indicating order this invoice was created in. *(added v23.08)*
- **amount\_msat** (msat, optional): The amount required to pay this invoice.
- **bolt12** (string, optional): The BOLT12 string.
- **updated\_index** (u64, optional): 1-based index indicating order this invoice was changed (only present if it has changed since creation). *(added v23.08)*

If **status** is "paid":
  - **pay\_index** (u64): Unique incrementing index for this payment.
  - **amount\_received\_msat** (msat): The amount actually received (could be slightly greater than *amount\_msat*, since clients may overpay).
  - **paid\_at** (u64): UNIX timestamp of when it was paid.
  - **payment\_preimage** (secret): Proof of payment.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "label": "payme for real!",
  "bolt12": "lni1qqg804wzdsyn8g4mf2yc22k8xvjpjzstwd5k6urvv5s8getnw3gzqp3zderpzxstt8927ynqg044h0egcd8n5h3n9g0u0v4h8ncc3yg02gqsykppqgkjyd3q5dv6gllh77kygly9c3kfy0d9xwyjyxsq2nq3c83u5vw4ngycqdwjkyvjm7apxnssu4qgwhfkd67ghs6n6k48v6uqczgt88p6tky96qmcmtl30xtt7jdakfyhzm8f0gny6f4d2ukx5gurem04z8lfd2wza5qs9pz6wp9vu7cm6n4wmmrz77y4w6z5xv4q93yudkdtkl5zmzdzuawzqqex7gd5v0x0r83pqj82udd542fl4krh50s0dkx47d0hd5wh77g52xxl75ccpkt35mc8n282wslju9ufyys2y8qqqqqqqqqqqqqqqpgqqqqqqqqqqqqp6f9jm7k9yqqqqqq2gpr96l99lfspt25zqnyfgu7hznmt2tzkjdt92d2wc3dsq7keph7w8gudjs46spfzqrlu4gqs9vppqdwjkyvjm7apxnssu4qgwhfkd67ghs6n6k48v6uqczgt88p6tky9muzqpze8kk43g0wh4h8qlac5lswwesrvsaxcza2f5j90c2h3ts8yzmn9g4mxqe89fngrqny8nf52xxuxep6548etda8lp876jr0nnxgdkdq",
  "payment_hash": "4c89473d714f6b52c56935655354ec45b007ad90dfce3a38d942ba8052200ffc",
  "amount_msat": 2,
  "status": "paid",
  "pay_index": 1,
  "amount_received_msat": 2,
  "paid_at": 1708640865,
  "payment_preimage": "305951ab02cb2ea5eb884dbfd8fb110b4e088ecb8338b3e84e8f9c70919c19bf",
  "description": "simple test",
  "expires_at": 1708640953,
  "created_index": 2,
  "updated_index": 1
}
```

ERRORS
------

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

lightning-fetchinvoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
