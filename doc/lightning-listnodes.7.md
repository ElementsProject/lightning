lightning-listnodes -- Command to get the list of nodes in the known network.
============================================================

SYNOPSIS
--------

**listnodes** \[id\]

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

On success, the command will return a list of nodes, each object represents a node, with the following details:

- *nodeid*: Hex-encoded pubkey of the node.

For nodes which have sent a node_announcement message, the following
are also returned:

- *alias*: The user-chosen node name as a string.
- *color*: The user-chosen node color as a hexadecimal string.
- *last_timestamp*: The last-received node_announcement message as a UNIX timestamp integer.
- *features*: Hex-encoded features bitstring.
- *addresses*: An array of the node's public addresses. Each address is represented by an object with the following properties:
  - *type*: Address type (`"ipv4"`, `"ipv6"`, `"torv2"` or `"torv3"`).
  - *address*: IP or `.onion` hidden service address as a string.
  - *port*: Port number as an integer.

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
