lightning-listpays -- Command for querying payment status
=========================================================

SYNOPSIS
--------

**listpays** [*bolt11*] [*payment\_hash*] [*status*]

DESCRIPTION
-----------

The **listpay** RPC command gets the status of all *pay* commands, or a
single one if either *bolt11* or *payment\_hash* was specified.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **pays** is returned.  It is an array of objects, where each object contains:

- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **status** (string): status of the payment (one of "pending", "failed", "complete")
- **created\_at** (u64): the UNIX timestamp showing when this payment was initiated
- **destination** (pubkey, optional): the final destination of the payment if known
- **completed\_at** (u64, optional): the UNIX timestamp showing when this payment was completed
- **label** (string, optional): the label, if given to sendpay
- **bolt11** (string, optional): the bolt11 string (if pay supplied one)
- **description** (string, optional): the description matching the bolt11 description hash (if pay supplied one)
- **bolt12** (string, optional): the bolt12 string (if supplied for pay: **experimental-offers** only).

If **status** is "complete":

  - **amount\_sent\_msat** (msat): The amount of millisatoshi we sent in order to pay (may include fees and not match amount\_msat)
  - **preimage** (secret): proof of payment
  - **amount\_msat** (msat, optional): The amount of millisatoshi we intended to send to the destination
  - **number\_of\_parts** (u64, optional): the number of parts for a successful payment (only if more than one).

If **status** is "failed":

  - **erroronion** (hex, optional): the error onion returned on failure, if any.

[comment]: # (GENERATE-FROM-SCHEMA-END)

The returned array is ordered by increasing **created\_at** fields.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-paystatus(7), lightning-listsendpays(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:e0cf61a1f37bd8d335fd40bb56c015d0e007480dfff58948c2bb28be6388f51c)
