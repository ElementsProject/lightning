lightning-listnodes -- Command to get the list of nodes in the known network.
============================================================

SYNOPSIS
--------

**listnodes** [*id*]

DESCRIPTION
-----------

The **listnodes** command returns nodes the node has learned about via gossip messages, or a single one if the node *id* was specified.

EXAMPLE JSON REQUEST
------------
```json
{
  "id": 82,
  "method": "listnodes",
  "params": {
    "id": "02e29856dab8ddd9044c18486e4cab79ec717b490447af2d4831e290e48d57638a"
  }
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **nodes** is returned.  It is an array of objects, where each object contains:
- **nodeid** (pubkey): the public key of the node
- **last_timestamp** (u32, optional): A node_announcement has been received for this node (UNIX timestamp)

If **last_timestamp** is present:
  - **alias** (string): The fun alias this node advertized (up to 32 characters)
  - **color** (hex): The favorite RGB color this node advertized (always 6 characters)
  - **features** (hex): BOLT #9 features bitmap this node advertized
  - **addresses** (array of objects): The addresses this node advertized:
    - **type** (string): Type of connection (one of "dns", "ipv4", "ipv6", "torv2", "torv3", "websocket")
    - **port** (u16): port number

    If **type** is "dns", "ipv4", "ipv6", "torv2" or "torv3":
      - **address** (string): address in expected format for **type**

If **option_will_fund** is present:
  - **option_will_fund** (object):
    - **lease_fee_base_msat** (msat): the fixed fee for a lease (whole number of satoshis)
    - **lease_fee_basis** (u32): the proportional fee in basis points (parts per 10,000) for a lease
    - **funding_weight** (u32): the onchain weight you'll have to pay for a lease
    - **channel_fee_max_base_msat** (msat): the maximum base routing fee this node will charge during the lease
    - **channel_fee_max_proportional_thousandths** (u32): the maximum proportional routing fee this node will charge during the lease (in thousandths, not millionths like channel_update)
    - **compact_lease** (hex): the lease as represented in the node_announcement

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

EXAMPLE JSON RESPONSE
-----
```json
{
   "nodes": [
      {
         "nodeid": "02e29856dab8ddd9044c14586e4cab79ec717b490447af2d4831e290e48d58638a",
         "alias": "some_alias",
         "color": "68f442",
         "last_timestamp": 1597213741,
         "features": "02a2a1",
         "addresses": [
            {
               "type": "ipv4",
               "address": "zzz.yy.xx.xx",
               "port": 9735
            }
         ]
      }
    ]
}
```


AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

FIXME:

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:85400c9c1741943e2e02935b4f14fd187a7db6056410e42adec07ef3c6772f5f)
