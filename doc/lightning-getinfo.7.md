lightning-getinfo -- Command to receive all information about the c-lightning node.
============================================================

SYNOPSIS
--------

**getinfo**

DESCRIPTION
-----------

The **getinfo** is a RPC command which is possible receive all node informations.


EXAMPLE JSON REQUEST
------------
```json
{
  "id": 82,
  "method": "getinfo",
  "params": {}
}
```

RETURN VALUE
------------

On success, an object with the following information is returned:

- *id*: A string that rappresents the public key of the node. It will rappresent the node on the public network.
- *alias*: A string that rappresents the alias of the node, by default is calculate from the public key (node id).
- *color*: A string that rappresents the color of the node.
- *num_peers*: An integer that rappresents the number of peer connect to the node.
- *num_pending_channels*: An integer that rappresents the number of channel with pending status.
- *num_active_channels*: A integer that rappresents the number of channel with the active status.
- *num_inactive_channels*: A integer that rappresents the number of channel with the inactive status.
- *address*: An array that rappresents all addresses of the node, each object inside the array contains the following proprieties:
  - *type*: A string that rappresents the type of the address (ipv4 or ipv6).
  - *address*: A string that rappresents the value of the address.
  - *port*: An integer that rappresents the port where the node are listening with this address.
- *binding*: An array that rappresents all addresses where the node is binded and is ready to receive message. Each object contains the same object type of the address propriety above.
- *version*: A string that rappresents the version of the node.
- *blockheight*: An integera that rappresents the blockchain height.
- *network*: A string that rappresents the type of network on the node are working (i.e: bitcoin, testnet, regtest).

On failure, one of the following error codes may be returned:

- -32602. Error in given parameters or some error happened during the command process.

EXAMPLE JSON RESPONSE
-----
```json
{
   "id": "02bf811f7571754f0b51e6d41a8885f5561041a7b14fac093e4cffb95749de1a8d",
   "alias": "SLICKERGOPHER",
   "color": "02bf81",
   "num_peers": 0,
   "num_pending_channels": 0,
   "num_active_channels": 0,
   "num_inactive_channels": 0,
   "address": [
      {
         "type": "torv3",
         "address": "fp463inc4w3lamhhduytrwdwq6q6uzugtaeapylqfc43agrdnnqsheyd.onion",
         "port": 9736
      },
      {
         "type": "torv3",
         "address": "ifnntp5ak4homxrti2fp6ckyllaqcike447ilqfrgdw64ayrmkyashid.onion",
         "port": 9736
      }
   ],
   "binding": [
      {
         "type": "ipv4",
         "address": "127.0.0.1",
         "port": 9736
      }
   ],
   "version": "0.9.0",
   "blockheight": 644297,
   "network": "bitcoin",
   "msatoshi_fees_collected": 0,
   "fees_collected_msat": "0msat",
   "lightning-dir": "/media/vincent/Maxtor/C-lightning/node/bitcoin"
}

```


AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.


SEE ALSO
------

lightning-connect(7), lightning-fundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
