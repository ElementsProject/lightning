lightning-getinfo -- Command to receive all information about the c-lightning node.
============================================================

SYNOPSIS
--------

**getinfo**

DESCRIPTION
-----------

The **getinfo** gives a summary of the current running node.


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

- *id*: A string that represents the public key of the node. It will represents the node on the public network.
- *alias*: A string that represents the alias of the node, by default is calculate from the public key (node id).  This is just for fun; the name can be anything and is not unique!
- *color*: A string that represents the preferred color of the node.
- *num_peers*: An integer that represents the number of peer connect to the node.
- *num_pending_channels*: An integer that represents the number of channel which are still awaiting opening confirmation.
- *num_active_channels*: A integer that represents the number of channel which are currently open.
- *num_inactive_channels*: A integer that represents the number of channel which are closing.
- *address*: An array that represents all published addresses of the node, each object inside the array contains the following proprieties:
  - *type*: A string that represents the type of the address (currently `ipv4`, `ipv6`, `torv3` or `torv4`).
  - *address*: A string that represents the value of the address.
  - *port*: An integer that represents the port where the node is listening with this address.
- *binding*: An array that represents all addresses where the node is binded. Each object contains the same object type of the address propriety above.
- *version*: A string that represents the version of the node.
- *blockheight*: An integer that represents the blockchain height.
- *network*: A string that represents the type of network on the node are working (e.g: `bitcoin`, `testnet`, or `regtest`).

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters or some error happened during the command process.

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

lightning-connect(7), lightning-fundchannel(7), lightning-listconfigs(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
