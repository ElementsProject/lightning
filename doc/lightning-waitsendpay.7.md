lightning-waitsendpay -- Command for sending a payment via a route
==================================================================

SYNOPSIS
--------

**waitsendpay** *payment\_hash* [*timeout*] [*partid* *groupid*] 

DESCRIPTION
-----------

The **waitsendpay** RPC command polls or waits for the status of an outgoing payment that was initiated by a previous **sendpay** invocation.

If the payment completed with success, this command returns with success. Otherwise, if the payment completed with failure, this command returns an error.

- **payment\_hash** (hash): The hash of the *payment\_preimage*.
- **timeout** (u32, optional): A timeout in seconds, for this RPC command to return. If the *timeout* is provided and the given amount of time passes without the payment definitely succeeding or definitely failing, this command returns with a 200 error code (payment still in progress). If *timeout* is not provided this call will wait indefinitely. Indicating a *timeout* of 0 effectively makes this call a pollable query of the status of the payment.
- **partid** (u64, optional): Unique ID within this (multi-part) payment. It must match that of the **sendpay** command.
- **groupid** (u64, optional): Grouping key to disambiguate multiple attempts to pay the same payment\_hash.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:waitsendpay#1",
  "method": "waitsendpay",
  "params": {
    "payment_hash": "072b1d20f4a7c757a56d5fb10eaed40b58b68849da41fe396cdbd2d81692875a",
    "timeout": null,
    "partid": null,
    "groupid": null
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **created\_index** (u64): 1-based index indicating order this payment was created in. *(added v23.11)*
- **id** (u64): Old synonym for created\_index.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **status** (string) (always "complete"): Status of the payment.
- **created\_at** (u64): The UNIX timestamp showing when this payment was initiated.
- **amount\_sent\_msat** (msat): The amount sent.
- **groupid** (u64, optional): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment\_hash.
- **amount\_msat** (msat, optional): The amount delivered to destination (if known).
- **destination** (pubkey, optional): The final destination of the payment if known.
- **updated\_index** (u64, optional): 1-based index indicating order this payment was changed (only present if it has changed since creation). *(added v23.11)*
- **completed\_at** (number, optional): The UNIX timestamp showing when this payment was completed.
- **label** (string, optional): The label, if given to sendpay.
- **partid** (u64, optional): The *partid*, if given to sendpay.
- **bolt11** (string, optional): The bolt11 string (if pay supplied one).
- **bolt12** (string, optional): The bolt12 string (if supplied for pay: **experimental-offers** only).

If **status** is "complete":
  - **payment\_preimage** (secret): The proof of payment: SHA256 of this **payment\_hash**.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "created_index": 1,
  "id": 1,
  "payment_hash": "072b1d20f4a7c757a56d5fb10eaed40b58b68849da41fe396cdbd2d81692875a",
  "groupid": 1,
  "updated_index": 1,
  "destination": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
  "amount_msat": 11000000,
  "amount_sent_msat": 11000000,
  "created_at": 1706152930,
  "completed_at": 1706152933,
  "status": "complete",
  "payment_preimage": "af7ba559629f719c04c43a82767fe3622790a539164d6270db07f765203e574b",
  "bolt11": "lnbcrt110u1pjmr5lzsp5sfjyj3xn7ux592k36hmmt4ax98n6lgct22wvj54yck0upcmep63qpp5qu436g855lr40ftdt7csatk5pdvtdzzfmfqluwtvm0fds95jsadqdpq0pzk7s6j8y69xjt6xe25j5j4g44hsatdxqyjw5qcqp99qxpqysgquwma3zrw4cd8e8j4u9uh4gxukaacckse64kx2l9dqv8rvrysdq5r5dt38t9snqj9u5ar07h2exr4fg56wpudkhkk7gtxlyt72ku5fpqqd4fnlk"
}
```

ERRORS
------

On error, and even if the error occurred from a node other than the final destination, the route table will no longer be updated. Use the *exclude* parameter of the `getroute` command to ignore the failing route.

- -1: Catchall nonspecific error.
- 200: Timed out before the payment could complete.
- 202: Unparseable onion reply. The *data* field of the error will have an *onionreply* field, a hex string representation of the raw onion reply.
- 203: Permanent failure at destination. The *data* field of the error will be routing failure object.
- 204: Failure along route; retry a different route. The *data* field of the error will be routing failure object.
- 208: A payment for *payment\_hash* was never made and there is nothing to wait for.
- 209: The payment already failed, but the reason for failure was not stored. This should only occur when querying failed payments on very old databases.

A routing failure object has the fields below:

*erring\_index*: The index of the node along the route that reported the error. 0 for the local node, 1 for the first hop, and so on.
*erring\_node*: The hex string of the pubkey id of the node that reported the error.
*erring\_channel*: The short channel ID of the channel that has the error (or the final channel if the destination raised the error).
*erring\_direction*: The direction of traversing the *erring\_channel*:
*failcode*: The failure code, as per BOLT #4.
*failcodename*: The human-readable name corresponding to *failcode*, if known.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-sendpay(7), lightning-pay(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
