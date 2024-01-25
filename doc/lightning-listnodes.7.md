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
- **last\_timestamp** (u32, optional): A node\_announcement has been received for this node (UNIX timestamp)

If **last\_timestamp** is present:

  - **alias** (string): The fun alias this node advertized (up to 32 characters)
  - **color** (hex): The favorite RGB color this node advertized (always 6 characters)
  - **features** (hex): BOLT #9 features bitmap this node advertized
  - **addresses** (array of objects): The addresses this node advertized:
    - **type** (string): Type of connection (until 23.08, `websocket` was also allowed) (one of "dns", "ipv4", "ipv6", "torv2", "torv3")
    - **port** (u16): port number

    If **type** is "dns", "ipv4", "ipv6", "torv2" or "torv3":

      - **address** (string): address in expected format for **type**

If **option\_will\_fund** is present:

  - **option\_will\_fund** (object):
    - **lease\_fee\_base\_msat** (msat): the fixed fee for a lease (whole number of satoshis)
    - **lease\_fee\_basis** (u32): the proportional fee in basis points (parts per 10,000) for a lease
    - **funding\_weight** (u32): the onchain weight you'll have to pay for a lease
    - **channel\_fee\_max\_base\_msat** (msat): the maximum base routing fee this node will charge during the lease
    - **channel\_fee\_max\_proportional\_thousandths** (u32): the maximum proportional routing fee this node will charge during the lease (in thousandths, not millionths like channel\_update)
    - **compact\_lease** (hex): the lease as represented in the node\_announcement

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

[comment]: # ( SHA256STAMP:54744d83c606d436d62335f02525804cbbfa9c488e45f8b776a4b4c99a251f08)
