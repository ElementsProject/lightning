lightning-listforwards -- Command showing all htlcs and their information
=========================================================================

SYNOPSIS
--------

**listforwards** [*status*] [*in\_channel*] [*out\_channel*] [*index* [*start*] [*limit*]]

DESCRIPTION
-----------

The **listforwards** RPC command displays all htlcs that have been attempted to be forwarded by the Core Lightning node.

- **status** (string, optional) (one of "offered", "settled", "local\_failed", "failed"): If specified, then only the forwards with the given status are returned.
- **in\_channel** (short\_channel\_id, optional): Only the matching forwards on the given inbound channel are returned.
- **out\_channel** (short\_channel\_id, optional): Only the matching forwards on the given outbount channel are returned.
- **index** (string, optional) (one of "created", "updated"): If neither *in\_channel* nor *out\_channel* is specified, it controls ordering. The default is `created`. *(added v23.11)*
- **start** (u64, optional): If `index` is specified, `start` may be specified to start from that value, which is generally returned from lightning-wait(7). *(added v23.11)*
- **limit** (u32, optional): If `index` is specified, `limit` can be used to specify the maximum number of entries to return. *(added v23.11)*

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listforwards#1",
  "method": "listforwards",
  "params": {
    "status": null,
    "in_channel": null,
    "out_channel": null,
    "index": null,
    "start": null,
    "limit": null
  }
}
{
  "id": "example:listforwards#2",
  "method": "listforwards",
  "params": {
    "in_channel": "0x1x2",
    "out_channel": "0x2x3",
    "status": "settled"
  }
}
```

RETURN VALUE
------------

On success, an object containing **forwards** is returned. It is an array of objects, where each object contains:

- **created\_index** (u64): 1-based index indicating order this forward was created in. *(added v23.11)*
- **in\_channel** (short\_channel\_id): The channel that received the HTLC.
- **in\_msat** (msat): The value of the incoming HTLC.
- **status** (string) (one of "offered", "settled", "local\_failed", "failed"): Still ongoing, completed, failed locally, or failed after forwarding.
- **received\_time** (number): The UNIX timestamp when this was received.
- **in\_htlc\_id** (u64, optional): The unique HTLC id the sender gave this (not present if incoming channel was closed before upgrade to v22.11).
- **out\_channel** (short\_channel\_id, optional): The channel that the HTLC (trying to) forward to.
- **out\_htlc\_id** (u64, optional): The unique HTLC id we gave this when sending (may be missing even if out\_channel is present, for old forwards before v22.11).
- **updated\_index** (u64, optional): 1-based index indicating order this forward was changed (only present if it has changed since creation). *(added v23.11)*
- **style** (string, optional) (one of "legacy", "tlv"): Either a legacy onion format or a modern tlv format.

If **out\_msat** is present:
  - **fee\_msat** (msat): The amount this paid in fees.
  - **out\_msat** (msat): The amount we sent out the *out\_channel*.

If **status** is "settled" or "failed":
  - **resolved\_time** (number): The UNIX timestamp when this was resolved.

If **status** is "local\_failed" or "failed":
  - **failcode** (u32, optional): The numeric onion code returned.
  - **failreason** (string, optional): The name of the onion code returned.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "forwards": [
    {
      "created_index": 1,
      "updated_index": 1,
      "in_channel": "103x1x0",
      "in_htlc_id": 0,
      "out_channel": "104x1x0",
      "out_htlc_id": 0,
      "in_msat": 100001001,
      "out_msat": 100000000,
      "fee_msat": 1001,
      "status": "settled",
      "style": "tlv",
      "received_time": 1706229285.5934534,
      "resolved_time": 1706229288.830004
    },
    {
      "created_index": 2,
      "updated_index": 2,
      "in_channel": "103x1x0",
      "in_htlc_id": 1,
      "out_channel": "105x1x0",
      "out_htlc_id": 0,
      "in_msat": 100001001,
      "out_msat": 100000000,
      "fee_msat": 1001,
      "status": "failed",
      "style": "tlv",
      "received_time": 1706229290.0289993,
      "resolved_time": 1706229292.9487684
    },
    {
      "created_index": 3,
      "updated_index": 3,
      "in_channel": "103x1x0",
      "in_htlc_id": 2,
      "out_channel": "106x1x0",
      "out_htlc_id": 0,
      "in_msat": 100001000,
      "out_msat": 99999999,
      "fee_msat": 1001,
      "status": "local_failed",
      "failcode": 16392,
      "failreason": "WIRE_PERMANENT_CHANNEL_FAILURE",
      "style": "tlv",
      "received_time": 1706229295.3175724
    }
  ]
}
{
  "forwards": []
}
```

AUTHOR
------

Rene Pickhardt <<r.pickhardt@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-autoclean-status(7), lightning-getinfo(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
