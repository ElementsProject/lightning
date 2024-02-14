lightning-sendpay -- Low-level command for sending a payment via a route
========================================================================

SYNOPSIS
--------

**sendpay** *route* *payment\_hash* [*label*] [*amount\_msat*] [*bolt11*] [*payment\_secret*] [*partid*] [*localinvreqid*] [*groupid*] [*payment\_metadata*] [*description*] 

DESCRIPTION
-----------

The **sendpay** RPC command attempts to send funds associated with the given *payment\_hash*, along a route to the final destination in the route.

Generally, a client would call lightning-getroute(7) to resolve a route, then use **sendpay** to send it. If it fails, it would call lightning-getroute(7) again to retry. If the route is empty, a payment-to-self is attempted.

The response will occur when the payment is on its way to the destination. The **sendpay** RPC command does not wait for definite success or definite failure of the payment (except for already-succeeded payments, or to-self payments). Instead, use the **waitsendpay** RPC command to poll or wait for definite success or definite failure.

Once a payment has succeeded, calls to **sendpay** with the same *payment\_hash* but a different *amount\_msat* or destination will fail; this prevents accidental multiple payments. Calls to **sendpay** with the same *payment\_hash*, *amount\_msat*, and destination as a previous successful payment (even if a different route or *partid*) will return immediately with success.

- **route** (array of objects):
  - **id** (pubkey): The node at the end of this hop.
  - **channel** (short\_channel\_id): The channel joining these nodes.
  - **delay** (u32): The total CLTV expected by the node at the end of this hop.
  - **amount\_msat** (msat): The amount expected by the node at the end of this hop.
- **payment\_hash** (hash): The hash of the payment\_preimage.
- **label** (string, optional): The label provided when creating the invoice\_request.
- **amount\_msat** (msat, optional): Amount must be provided if *partid* is non-zero, or the payment is to-self, otherwise it must be equal to the final amount to the destination. it can be a whole number, or a whole number ending in *msat* or *sat*, or a number with three decimal places ending in *sat*, or a number with 1 to 11 decimal places ending in *btc*. The default is in millisatoshi precision.
- **bolt11** (string, optional): Bolt11 invoice to pay. If provided, will be returned in *waitsendpay* and *listsendpays* results.
- **payment\_secret** (secret, optional): Value that the final recipient requires to accept the payment, as defined by the `payment_data` field in BOLT 4 and the `s` field in the BOLT 11 invoice format. It is required if *partid* is non-zero.
- **partid** (u64, optional): Must not be provided for self-payments. If provided and non-zero, allows for multiple parallel partial payments with the same *payment\_hash*. The *amount\_msat* amount (which must be provided) for each **sendpay** with matching *payment\_hash* must be equal, and **sendpay** will fail if there are differing values given.
- **localinvreqid** (hex, optional): Indicates that this payment is being made for a local invoice\_request. This ensures that we only send a payment for a single-use invoice\_request once.
- **groupid** (u64, optional): Allows you to attach a number which appears in **listsendpays** so payments can be identified as part of a logical group. The *pay* plugin uses this to identify one attempt at a MPP payment, for example.
- **payment\_metadata** (hex, optional): Placed in the final onion hop TLV. *(added v0.11.0)*
- **description** (string, optional): Description used in the invoice. *(added v0.11.0)*

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:sendpay#1",
  "method": "sendpay",
  "params": {
    "route": [
      {
        "amount_msat": 11000000,
        "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
        "delay": 5,
        "channel": "103x1x0"
      }
    ],
    "payment_hash": "072b1d20f4a7c757a56d5fb10eaed40b58b68849da41fe396cdbd2d81692875a",
    "label": null,
    "amount_msat": null,
    "bolt11": "lnbcrt110u1pjmr5lzsp5sfjyj3xn7ux592k36hmmt4ax98n6lgct22wvj54yck0upcmep63qpp5qu436g855lr40ftdt7csatk5pdvtdzzfmfqluwtvm0fds95jsadqdpq0pzk7s6j8y69xjt6xe25j5j4g44hsatdxqyjw5qcqp99qxpqysgquwma3zrw4cd8e8j4u9uh4gxukaacckse64kx2l9dqv8rvrysdq5r5dt38t9snqj9u5ar07h2exr4fg56wpudkhkk7gtxlyt72ku5fpqqd4fnlk",
    "payment_secret": "82644944d3f70d42aad1d5f7b5d7a629e7afa30b529cc952a4c59fc0e3790ea2",
    "partid": null,
    "groupid": null,
    "payment_metadata": null
  }
}
{
  "id": "example:sendpay#2",
  "method": "sendpay",
  "params": {
    "route": [
      {
        "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
        "channel": "103x1x0",
        "direction": 1,
        "amount_msat": 4211,
        "style": "tlv",
        "delay": 24
      },
      {
        "id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
        "channel": "105x1x0",
        "direction": 0,
        "amount_msat": 3710,
        "style": "tlv",
        "delay": 16
      },
      {
        "id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
        "channel": "107x1x0",
        "direction": 1,
        "amount_msat": 3210,
        "style": "tlv",
        "delay": 8
      }
    ],
    "payment_hash": "bc747053329402620a26bdc187cd134cdb699130d85be499ecd24160aff04c5c",
    "label": null,
    "amount_msat": null,
    "bolt11": null,
    "payment_secret": "c36a2fe9aced78c06960e2f21b369ed03f0492c97e53ba3b662163bcdaf1d7fa",
    "partid": null,
    "groupid": null,
    "payment_metadata": null
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **created\_index** (u64): 1-based index indicating order this payment was created in. *(added v23.11)*
- **id** (u64): Old synonym for created\_index.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **status** (string) (one of "pending", "complete"): Status of the payment (could be complete if already sent previously).
- **created\_at** (u64): The UNIX timestamp showing when this payment was initiated.
- **amount\_sent\_msat** (msat): The amount sent.
- **updated\_index** (u64, optional): 1-based index indicating order this payment was changed (only present if it has changed since creation). *(added v23.11)*
- **groupid** (u64, optional): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment\_hash.
- **amount\_msat** (msat, optional): The amount delivered to destination (if known).
- **destination** (pubkey, optional): The final destination of the payment if known.
- **completed\_at** (u64, optional): The UNIX timestamp showing when this payment was completed.
- **label** (string, optional): The *label*, if given to sendpay.
- **partid** (u64, optional): The *partid*, if given to sendpay.
- **bolt11** (string, optional): The bolt11 string (if supplied).
- **bolt12** (string, optional): The bolt12 string (if supplied: **experimental-offers** only).

If **status** is "complete":
  - **payment\_preimage** (secret): The proof of payment: SHA256 of this **payment\_hash**.

If **status** is "pending":
  - **message** (string): Monitor status with listpays or waitsendpay.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "message": "Monitor status with listpays or waitsendpay",
  "created_index": 1,
  "id": 1,
  "payment_hash": "072b1d20f4a7c757a56d5fb10eaed40b58b68849da41fe396cdbd2d81692875a",
  "groupid": 1,
  "destination": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
  "amount_msat": 11000000,
  "amount_sent_msat": 11000000,
  "created_at": 1706152930,
  "status": "pending",
  "bolt11": "lnbcrt110u1pjmr5lzsp5sfjyj3xn7ux592k36hmmt4ax98n6lgct22wvj54yck0upcmep63qpp5qu436g855lr40ftdt7csatk5pdvtdzzfmfqluwtvm0fds95jsadqdpq0pzk7s6j8y69xjt6xe25j5j4g44hsatdxqyjw5qcqp99qxpqysgquwma3zrw4cd8e8j4u9uh4gxukaacckse64kx2l9dqv8rvrysdq5r5dt38t9snqj9u5ar07h2exr4fg56wpudkhkk7gtxlyt72ku5fpqqd4fnlk"
}
{
  "message": "Monitor status with listpays or waitsendpay",
  "created_index": 2,
  "id": 2,
  "payment_hash": "bc747053329402620a26bdc187cd134cdb699130d85be499ecd24160aff04c5c",
  "groupid": 1,
  "destination": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
  "amount_msat": 3210,
  "amount_sent_msat": 4211,
  "created_at": 1708624260,
  "status": "pending"
}
```

ERRORS
------

On error, if the error occurred from a node other than the final destination, the route table will be updated so that lightning-getroute(7) should return an alternate route (if any). An error from the final destination implies the payment should not be retried.

- -1: Catchall nonspecific error.
- 201: Already paid with this *hash* using different amount or destination.
- 202: Unparseable onion reply. The *data* field of the error will have an *onionreply* field, a hex string representation of the raw onion reply.
- 203: Permanent failure at destination. The *data* field of the error will be routing failure object.
- 204: Failure along route; retry a different route. The *data* field of the error will be routing failure object.
- 212: *localinvreqid* refers to an invalid, or used, local invoice\_request.

A routing failure object has the fields below:

*erring\_index*: The index of the node along the route that reported the error. 0 for the local node, 1 for the first hop, and so on.
*erring\_node*: The hex string of the pubkey id of the node that reported the error.
*erring\_channel*: The short channel ID of the channel that has the error, or *0:0:0* if the destination node raised the error. In addition *erring\_direction* will indicate which direction of the channel caused the failure.
*failcode*: The failure code, as per BOLT #4.
*channel\_update*: The hex string of the *channel\_update* message received from the remote node. Only present if error is from the remote node and the *failcode* has the UPDATE bit set, as per BOLT #4.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoice(7), lightning-delinvoice(7), lightning-getroute(7), lightning-invoice(7), lightning-pay(7), lightning-waitsendpay(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
