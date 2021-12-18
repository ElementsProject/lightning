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

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **id** (pubkey): The public key unique to this node
- **alias** (string): The fun alias this node will advertize (up to 32 characters)
- **color** (hex): The favorite RGB color this node will advertize (always 6 characters)
- **num_peers** (u32): The total count of peers, connected or with channels
- **num_pending_channels** (u32): The total count of channels being opened
- **num_active_channels** (u32): The total count of channels in normal state
- **num_inactive_channels** (u32): The total count of channels waiting for opening or closing transactions to be mined
- **version** (string): Identifies what bugs you are running into
- **lightning-dir** (string): Identifies where you can find the configuration and other related files
- **blockheight** (u32): The highest block height we've learned
- **network** (string): represents the type of network on the node are working (e.g: `bitcoin`, `testnet`, or `regtest`)
- **fees_collected_msat** (msat): Total routing fees collected by this node
- **address** (array of objects, optional): The addresses we announce to the world:
  - **type** (string): Type of connection (one of "dns", "ipv4", "ipv6", "torv2", "torv3", "websocket")
  - **port** (u16): port number

  If **type** is "dns", "ipv4", "ipv6", "torv2" or "torv3":
    - **address** (string): address in expected format for **type**
- **binding** (array of objects, optional): The addresses we are listening on:
  - **type** (string): Type of connection (one of "local socket", "ipv4", "ipv6", "torv2", "torv3")
  - **address** (string, optional): address in expected format for **type**
  - **port** (u16, optional): port number
  - **socket** (string, optional): socket filename (only if **type** is "local socket")

The following warnings may also be returned:
- **warning_bitcoind_sync**: Bitcoind is not up-to-date with network.
- **warning_lightningd_sync**: Lightningd is still loading latest blocks from bitcoind.

[comment]: # (GENERATE-FROM-SCHEMA-END)

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
[comment]: # ( SHA256STAMP:90a3bacb6cb4456119afee8e60677c29bf5f46c4cd950e660a9f9c8e0433b473)
