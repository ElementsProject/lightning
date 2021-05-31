lightning-listpays -- Command for querying payment status
=========================================================

SYNOPSIS
--------

**listpays** \[bolt11\] \[payment_hash\]

DESCRIPTION
-----------

The **listpay** RPC command gets the status of all *pay* commands, or a
single one if either *bolt11* or *payment_hash* was specified.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **pays** is returned.  It is an array of objects, where each object contains:
- **payment_hash** (hex): the hash of the *payment_preimage* which will prove payment (always 64 characters)
- **status** (string): status of the payment (one of "pending", "failed", "complete")
- **created_at** (u64): the UNIX timestamp showing when this payment was initiated
- **destination** (pubkey, optional): the final destination of the payment if known
- **label** (string, optional): the label, if given to sendpay
- **bolt11** (string, optional): the bolt11 string (if pay supplied one)
- **bolt12** (string, optional): the bolt12 string (if supplied for pay: **experimental-offers** only).

If **status** is "pending" or "complete":
  - **amount_sent_msat** (msat): the amount we actually sent, including fees
  - **amount_msat** (msat, optional): the amount the destination received, if known

If **status** is "complete":
  - **preimage** (hex): proof of payment (always 64 characters)
  - **number_of_parts** (u64, optional): the number of parts for a successful payment (only if more than one).

If **status** is "failed":
  - **erroronion** (hex, optional): the error onion returned on failure, if any.
[comment]: # (GENERATE-FROM-SCHEMA-END)

The returned array is ordered by increasing **created_at** fields.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-paystatus(7), lightning-listsendpays(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:12e7b91fc59ee65b61d9aba4e8586fda8fbb524a7e548ffa36862e204952c46b)
