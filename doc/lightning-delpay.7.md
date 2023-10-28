lightning-delpay -- Command for removing a completed or failed payment
============================================================

SYNOPSIS
--------

**delpay** *payment\_hash* *status* [*partid* *groupid*]

DESCRIPTION
-----------

The **delpay** RPC command deletes a payment with the given `payment_hash` if its status is either `complete` or `failed`. Deleting a `pending` payment is an error.  If *partid* and *groupid* are not specified, all payment parts with matchin status are deleted.

- *payment\_hash*: The unique identifier of a payment.
- *status*: Expected status of the payment.
- *partid*: Specific partid to delete (must be paired with *groupid*)
- *groupid*: Specific groupid to delete (must be paired with *partid*)

Only deletes if the payment status matches.

EXAMPLE JSON REQUEST
------------
```json
{
  "id": 82,
  "method": "delpay",
  "params": {
    "payment_hash": "4fa2f1b001067ec06d7f95b8695b8acd9ef04c1b4d1110e3b94e1fa0687bb1e0",
    "status": "complete"
  }
}
```

RETURN VALUE
------------

The returned format is the same as lightning-listsendpays(7).  If the
payment is a multi-part payment (MPP) the command return a list of
payments will be returned -- one payment object for each partid.

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **payments** is returned.  It is an array of objects, where each object contains:

- **created\_index** (u64): 1-based index indicating order this payment was created in *(added v23.11)*
- **id** (u64): old synonym for created\_index
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **status** (string): status of the payment (one of "pending", "failed", "complete")
- **amount\_sent\_msat** (msat): the amount we actually sent, including fees
- **created\_at** (u64): the UNIX timestamp showing when this payment was initiated
- **partid** (u64, optional): unique ID within this (multi-part) payment
- **destination** (pubkey, optional): the final destination of the payment if known
- **amount\_msat** (msat, optional): the amount the destination received, if known
- **updated\_index** (u64, optional): 1-based index indicating order this payment was changed (only present if it has changed since creation) *(added v23.11)*
- **completed\_at** (u64, optional): the UNIX timestamp showing when this payment was completed
- **groupid** (u64, optional): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment\_hash
- **payment\_preimage** (secret, optional): proof of payment
- **label** (string, optional): the label, if given to sendpay
- **bolt11** (string, optional): the bolt11 string (if pay supplied one)
- **bolt12** (string, optional): the bolt12 string (if supplied for pay: **experimental-offers** only).
- **erroronion** (hex, optional): the error onion returned on failure, if any.

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, an error is returned. If the lightning process fails before responding, the
caller should use lightning-listsentpays(7) or lightning-listpays(7) to query whether this payment was deleted or not.

The following error codes may occur:

- -32602: Parameter missed or malformed;
- 211: Payment status mismatch. Check the correct status via **paystatus**;
- 208: Payment with payment\_hash not found.

EXAMPLE JSON RESPONSE
-----
```json
{
   "payments": [
      {
         "id": 2,
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

```


AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-listpays(7), lightning-listsendpays(7), lightning-paystatus(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:d390a3db57ea9ab02ce8d2613ba0396f717658fb972ccc9531fd7da0f4eb8ab4)
