lightning-delpay -- Command for removing a completed or failed payment
======================================================================

SYNOPSIS
--------

**delpay** *payment\_hash* *status* [*partid* *groupid*] 

DESCRIPTION
-----------

The **delpay** RPC command deletes a payment with the given `payment_hash` if its status is either `complete` or `failed`. If *partid* and *groupid* are not specified, all payment parts with matchin status are deleted.

- **payment\_hash** (hash): The unique identifier of a payment.
- **status** (string) (one of "complete", "failed"): Expected status of the payment. Only deletes if the payment status matches. Deleting a `pending` payment will return an error.
- **partid** (u64, optional): Specific partid to delete (must be paired with *groupid*).
- **groupid** (u64, optional): Specific groupid to delete (must be paired with *partid*).

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:delpay#1",
  "method": "delpay",
  "params": {
    "payment_hash": "4fa2f1b001067ec06d7f95b8695b8acd9ef04c1b4d1110e3b94e1fa0687bb1e0",
    "status": "complete"
  }
}
{
  "id": "example:delpay#2",
  "method": "delpay",
  "params": [
    "c9d4547473d0d646f1fdd8ca7f01803e4d31ceab01df33c79456f9c24b04034e",
    "failed"
  ]
}
{
  "id": "example:delpay#3",
  "method": "delpay",
  "params": {
    "payment_hash": "bbc35e0a46d1483292a4ff8d4daaceaab8c3c084dd835be4128785b52e469c64",
    "status": "complete",
    "groupid": 1,
    "partid": 1
  }
}
```

RETURN VALUE
------------

The returned format is the same as lightning-listsendpays(7). If the payment is a multi-part payment (MPP) the command return a list of payments will be returned -- one payment object for each partid.
On success, an object containing **payments** is returned. It is an array of objects, where each object contains:

- **created\_index** (u64): 1-based index indicating order this payment was created in. *(added v23.11)*
- **id** (u64): Old synonym for created\_index.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **status** (string) (one of "pending", "failed", "complete"): Status of the payment.
- **amount\_sent\_msat** (msat): The amount we actually sent, including fees.
- **created\_at** (u64): The UNIX timestamp showing when this payment was initiated.
- **partid** (u64, optional): Unique ID within this (multi-part) payment.
- **destination** (pubkey, optional): The final destination of the payment if known.
- **amount\_msat** (msat, optional): The amount the destination received, if known.
- **updated\_index** (u64, optional): 1-based index indicating order this payment was changed (only present if it has changed since creation). *(added v23.11)*
- **completed\_at** (u64, optional): The UNIX timestamp showing when this payment was completed.
- **groupid** (u64, optional): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment\_hash.
- **payment\_preimage** (secret, optional): Proof of payment.
- **label** (string, optional): The label, if given to sendpay.
- **bolt11** (string, optional): The bolt11 string (if pay supplied one).
- **bolt12** (string, optional): The bolt12 string (if supplied for pay: **experimental-offers** only).
- **erroronion** (hex, optional): The error onion returned on failure, if any.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "payments": [
    {
      "id": 1,
      "payment_hash": "8dfd6538eeb33811c9114a75f792a143728d7f05643f38c3d574d3097e8910c0",
      "destination": "0219f8900ee78a89f050c24d8b69492954f9fdbabed753710845eb75d3a75a5880",
      "msatoshi": 1000,
      "amount_msat": "1000msat",
      "msatoshi_sent": 1000,
      "amount_sent_msat": "1000msat",
      "created_at": 1596224858,
      "status": "complete",
      "payment_preimage": "35bd4e2b481a1a84a22215b5372672cf81460a671816960ddb206464359e1822",
      "bolt11": "lntb10n1p0jga20pp53h7k2w8wkvuprjg3ff6l0y4pgdeg6lc9vsln3s74wnfsjl5fzrqqdqdw3jhxazldahx2xqyjw5qcqp2sp5wut5jnhr6n7jd5747ky2g5flmw7hgx9yjnqzu60ps2jf6f7tc0us9qy9qsqu2a0k37nckl62005p69xavlkydkvhnypk4dphffy4x09zltwh9437ad7xkl83tefdarzhu5t30ju5s56wlrg97qkx404pq3srfc425cq3ke9af"
    }
  ]
}
{
  "payments": [
    {
      "created_index": 2,
      "id": 2,
      "payment_hash": "c9d4547473d0d646f1fdd8ca7f01803e4d31ceab01df33c79456f9c24b04034e",
      "groupid": 1,
      "updated_index": 2,
      "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
      "amount_msat": 100000,
      "amount_sent_msat": 100002,
      "created_at": 1706316468,
      "completed_at": 1706316471,
      "status": "failed",
      "bolt11": "lnbcrt1u1pjmg54nsp5ke626txv6wwwmqmpuy63t3jnu9hqxwj880zsfkkj7jjqagdaz2sqpp5e829garn6rtydu0amr987qvq8exnrn4tq80n83u52muuyjcyqd8qdq8v3jhxccxqyjw5qcqp99qxpqysgqalktfwy9svsamvvvrzzzzpdaa4rh7n6s5p7t9lx7qv0raz4vnm9knkh5ury3u5cmnhx2gms98nxkclm3833uhjrlnzmftc685vz2f0gpfnjy4y"
    }
  ]
}
{
  "payments": [
    {
      "created_index": 3,
      "id": 3,
      "payment_hash": "bbc35e0a46d1483292a4ff8d4daaceaab8c3c084dd835be4128785b52e469c64",
      "groupid": 1,
      "updated_index": 3,
      "partid": 1,
      "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
      "amount_msat": 100000,
      "amount_sent_msat": 102100,
      "created_at": 1708641193,
      "completed_at": 1708641194,
      "status": "complete",
      "payment_preimage": "a6ebb1cfbf69e76200f196f1eafd28a3d850633499c223a7eb7a7dba3b995286"
    }
  ]
}
```

ERRORS
------

On failure, an error is returned. If the lightning process fails before responding, the
caller should use lightning-listsentpays(7) or lightning-listpays(7) to query whether this payment was deleted or not.

The following error codes may occur:

- -32602: Parameter missed or malformed;
- 211: Payment status mismatch. Check the correct status via **paystatus**;
- 208: Payment with payment\_hash not found.

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-listpays(7), lightning-listsendpays(7), lightning-paystatus(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
