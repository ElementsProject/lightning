lightning-listnodes -- Command to get the list of nodes in the own node network
============================================================

SYNOPSIS
--------

**listnodes** \[id\]

DESCRIPTION
-----------

The **listnodes** command returns nodes in the own node network, or a single one if the node *id* was specified.

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

- *nodeid*: A string that rappresents the node id.
- *alias*: A string that rappresents alias of the node on the network.
- *color*: A string that rappresents the personal color of the node.
- *last_timestamp*: An integer that rappresent the last timestamp.
- *features*: An string that rappresent the features value.
- *addresses*: An array that rappresent the addreses avaible, each address is rappresented with an object with the following properties:
  - *type*: A string that rappresent the type of address (ipv4 or ipv6).
  - *address*: A string that rappresent the address value.
  - *port*: An integer that rappresent the port number where the node are listening.
  
On failure, one of the following error codes may be returned:
 
- -32602. Error in given parameters.

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
