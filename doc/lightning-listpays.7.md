lightning-listpays -- Command for querying payment status
=========================================================

SYNOPSIS
--------

**listpays** [*bolt11*] [*payment\_hash*] [*status*] 

DESCRIPTION
-----------

The **listpay** RPC command gets the status of all *pay* commands, or a single one if either *bolt11* or *payment\_hash* was specified.

- **bolt11** (string, optional): Bolt11 string to get the payment details.
- **payment\_hash** (hash, optional): Payment hash to get the payment details.
- **status** (string, optional) (one of "pending", "complete", "failed"): To filter the payment by status.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listpays#1",
  "method": "listpays",
  "params": {
    "bolt11": "lnbcrt123n1pjmxp7qsp5hxu7u28y0nx4v689u3hwzdzse2w9yaylhheavf9dxvwtdup7pvespp5ha66gxse68j4n6755v7299dnmq4w34gp0znxu0xzahdc43zrg40qdq5v3jhxcmjd9c8g6t0dc6sxqrp7scqp9rzjqgkjyd3q5dv6gllh77kygly9c3kfy0d9xwyjyxsq2nq3c83u5vw4jqqqvuqqqqsqqqqqqqqpqqqqqzsqqc9qxpqysgqk74dvqlvr92ayy5s7x0r0u9xywez6wu4h8pfta386cw6x7cdrvn8pz87kyg5c930aent423gm9ylpaw5p35k72f02hg0s9dulg4d8fqpgj7gpm",
    "payment_hash": null,
    "status": null
  }
}
{
  "id": "example:listpays#2",
  "method": "listpays",
  "params": {
    "bolt11": "lnbcrt123n1pjmxp7qsp5u84368dz7yhzcqm955h96wdqch7uarasun45cr0vs5d8t0cv5avqpp5r9p0dp92guaatrmhf302m0dyj4n79gk93qu2l5tagfxq3dedgfqsdq5v3jhxcmjd9c8g6t0dc6qxqrp7scqp9rzjqgkjyd3q5dv6gllh77kygly9c3kfy0d9xwyjyxsq2nq3c83u5vw4jqqqvuqqqqsqqqqqqqqpqqqqqzsqqc9qxpqysgq46wu0fznfx27rcnyzhcttf8yqx3lwqs482yxlead0fyt8mefrrrj5m379fa5qukgquf9tnwsuj3nnfmwkzkfg6pyhzq6w8gauuh6m5cqgur64n",
    "payment_hash": null,
    "status": null
  }
}
```

RETURN VALUE
------------

On success, an object containing **pays** is returned. It is an array of objects, where each object contains:

- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **status** (string) (one of "pending", "failed", "complete"): Status of the payment.
- **created\_at** (u64): The UNIX timestamp showing when this payment was initiated.
- **destination** (pubkey, optional): The final destination of the payment if known.
- **completed\_at** (u64, optional): The UNIX timestamp showing when this payment was completed.
- **label** (string, optional): The label, if given to sendpay.
- **bolt11** (string, optional): The bolt11 string (if pay supplied one).
- **description** (string, optional): The description matching the bolt11 description hash (if pay supplied one).
- **bolt12** (string, optional): The bolt12 string (if supplied for pay: **experimental-offers** only).

If **status** is "complete":
  - **amount\_sent\_msat** (msat): The amount of millisatoshi we sent in order to pay (may include fees and not match amount\_msat).
  - **preimage** (secret): Proof of payment.
  - **amount\_msat** (msat, optional): The amount of millisatoshi we intended to send to the destination.
  - **number\_of\_parts** (u64, optional): The number of parts for a successful payment (only if more than one).

If **status** is "failed":
  - **erroronion** (hex, optional): The error onion returned on failure, if any.

The returned array is ordered by increasing **created\_at** fields.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "pays": [
    {
      "bolt11": "lnbcrt123n1pjmxp7qsp5hxu7u28y0nx4v689u3hwzdzse2w9yaylhheavf9dxvwtdup7pvespp5ha66gxse68j4n6755v7299dnmq4w34gp0znxu0xzahdc43zrg40qdq5v3jhxcmjd9c8g6t0dc6sxqrp7scqp9rzjqgkjyd3q5dv6gllh77kygly9c3kfy0d9xwyjyxsq2nq3c83u5vw4jqqqvuqqqqsqqqqqqqqpqqqqqzsqqc9qxpqysgqk74dvqlvr92ayy5s7x0r0u9xywez6wu4h8pfta386cw6x7cdrvn8pz87kyg5c930aent423gm9ylpaw5p35k72f02hg0s9dulg4d8fqpgj7gpm",
      "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
      "payment_hash": "bf75a41a19d1e559ebd4a33ca295b3d82ae8d50178a66e3cc2eddb8ac443455e",
      "status": "failed",
      "created_at": 1706231854,
      "amount_sent_msat": 0
    }
  ]
}
{
  "pays": [
    {
      "bolt11": "lnbcrt123n1pjmxp7qsp5u84368dz7yhzcqm955h96wdqch7uarasun45cr0vs5d8t0cv5avqpp5r9p0dp92guaatrmhf302m0dyj4n79gk93qu2l5tagfxq3dedgfqsdq5v3jhxcmjd9c8g6t0dc6qxqrp7scqp9rzjqgkjyd3q5dv6gllh77kygly9c3kfy0d9xwyjyxsq2nq3c83u5vw4jqqqvuqqqqsqqqqqqqqpqqqqqzsqqc9qxpqysgq46wu0fznfx27rcnyzhcttf8yqx3lwqs482yxlead0fyt8mefrrrj5m379fa5qukgquf9tnwsuj3nnfmwkzkfg6pyhzq6w8gauuh6m5cqgur64n",
      "destination": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
      "payment_hash": "1942f684aa473bd58f774c5eadbda49567e2a2c58838afd17d424c08b72d4241",
      "status": "complete",
      "created_at": 1706231849,
      "completed_at": 1706231854,
      "preimage": "89ce412a2089cbcb72a73ce755337cf693859ea58f21ef0d1caf286a9b0f2a7c",
      "amount_msat": 12300,
      "amount_sent_msat": 12301
    }
  ]
}
```

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-paystatus(7), lightning-listsendpays(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
