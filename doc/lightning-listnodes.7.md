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

- *nodeid*: A string that represents the node id.

For nodes which have sent a node_announcement message, the following
are also returned:

- *alias*: A string that represents alias of the node on the network.
- *color*: A string that represents the personal color of the node.
- *last_timestamp*: An integer that represents the timestamp of the last-received node_announcement message.
- *features*: A string that represents the features value.
- *addresses*: An array that represents the addreses avaible. Each address is represented with an object with the following properties:
  - *type*: A string that represents the address type (ipv4 or ipv6).
  - *address*: A string that represents the address value.
  - *port*: An integer that represents the port number where the node are listening.
  
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
