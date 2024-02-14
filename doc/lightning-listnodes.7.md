lightning-listnodes -- Command to get the list of nodes in the known network.
=============================================================================

SYNOPSIS
--------

**listnodes** [*id*] 

DESCRIPTION
-----------

The **listnodes** command returns nodes the node has learned about via gossip messages, or a single one if the node *id* was specified.

- **id** (pubkey, optional): The public key of the node to list.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listnodes#1",
  "method": "listnodes",
  "params": {
    "id": "02e29856dab8ddd9044c18486e4cab79ec717b490447af2d4831e290e48d57638a"
  }
}
{
  "id": "example:listnodes#2",
  "method": "listnodes",
  "params": {
    "id": null
  }
}
```

RETURN VALUE
------------

On success, an object containing **nodes** is returned. It is an array of objects, where each object contains:

- **nodeid** (pubkey): The public key of the node.
- **last\_timestamp** (u32, optional): A node\_announcement has been received for this node (UNIX timestamp).

If **last\_timestamp** is present:
  - **alias** (string) (up to 32 characters): The fun alias this node advertized.
  - **color** (hex) (always 6 characters): The favorite RGB color this node advertized.
  - **features** (hex): BOLT #9 features bitmap this node advertized.
  - **addresses** (array of objects): The addresses this node advertized.:
    - **type** (string) (one of "dns", "ipv4", "ipv6", "torv2", "torv3"): Type of connection (until 23.08, `websocket` was also allowed).
    - **port** (u16): Port number.

    If **type** is "dns", "ipv4", "ipv6", "torv2" or "torv3":
      - **address** (string): Address in expected format for **type**.

If **option\_will\_fund** is present:
  - **option\_will\_fund** (object):
    - **lease\_fee\_base\_msat** (msat): The fixed fee for a lease (whole number of satoshis).
    - **lease\_fee\_basis** (u32): The proportional fee in basis points (parts per 10,000) for a lease.
    - **funding\_weight** (u32): The onchain weight you'll have to pay for a lease.
    - **channel\_fee\_max\_base\_msat** (msat): The maximum base routing fee this node will charge during the lease.
    - **channel\_fee\_max\_proportional\_thousandths** (u32): The maximum proportional routing fee this node will charge during the lease (in thousandths, not millionths like channel\_update).
    - **compact\_lease** (hex): The lease as represented in the node\_announcement.

EXAMPLE JSON RESPONSE
---------------------

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
{
  "nodes": [
    {
      "nodeid": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "alias": "SILENTARTIST-v23.11-415-gd120eba",
      "color": "022d22",
      "last_timestamp": 1708624765,
      "features": "88a0000a8a5961",
      "addresses": []
    },
    {
      "nodeid": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
      "alias": "JUNIORBEAM-v23.11-415-gd120eba",
      "color": "0266e4",
      "last_timestamp": 1708624765,
      "features": "88a0000a8a5961",
      "addresses": []
    },
    {
      "nodeid": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
      "alias": "HOPPINGFIRE-v23.11-415-gd120eba",
      "color": "035d2b",
      "last_timestamp": 1708624765,
      "features": "88a0000a8a5961",
      "addresses": []
    },
    {
      "nodeid": "0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199",
      "alias": "JUNIORFELONY-v23.11-415-gd120eba",
      "color": "0382ce",
      "last_timestamp": 1708624766,
      "features": "88a0000a8a5961",
      "addresses": []
    }
  ]
}
```

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page,
but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

lightning-listchannels(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
