lightning-getinfo -- Command to receive all information about the Core Lightning node.
======================================================================================

SYNOPSIS
--------

**getinfo** 

DESCRIPTION
-----------

The **getinfo** gives a summary of the current running node.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:getinfo#1",
  "method": "getinfo",
  "params": {}
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **id** (pubkey): The public key unique to this node.
- **alias** (string) (up to 32 characters): The fun alias this node will advertize.
- **color** (hex) (always 6 characters): The favorite RGB color this node will advertize.
- **num\_peers** (u32): The total count of peers, connected or with channels.
- **num\_pending\_channels** (u32): The total count of channels being opened.
- **num\_active\_channels** (u32): The total count of channels in normal state.
- **num\_inactive\_channels** (u32): The total count of channels waiting for opening or closing transactions to be mined.
- **version** (string): Identifies what bugs you are running into.
- **lightning-dir** (string): Identifies where you can find the configuration and other related files.
- **blockheight** (u32): The highest block height we've learned.
- **network** (string): Represents the type of network on the node are working (e.g: `bitcoin`, `testnet`, or `regtest`).
- **fees\_collected\_msat** (msat): Total routing fees collected by this node.
- **address** (array of objects): The addresses we announce to the world.:
  - **type** (string) (one of "dns", "ipv4", "ipv6", "torv2", "torv3"): Type of connection (until 23.08, `websocket` was also allowed).
  - **port** (u16): Port number.

  If **type** is "dns", "ipv4", "ipv6", "torv2" or "torv3":
    - **address** (string): Address in expected format for **type**.
- **our\_features** (object, optional): Our BOLT #9 feature bits (as hexstring) for various contexts.:
  - **init** (hex): Features (incl. globalfeatures) in our init message, these also restrict what we offer in open\_channel or accept in accept\_channel.
  - **node** (hex): Features in our node\_announcement message.
  - **channel** (hex): Negotiated channel features we (as channel initiator) publish in the channel\_announcement message.
  - **invoice** (hex): Features in our BOLT11 invoices.
- **binding** (array of objects, optional): The addresses we are listening on.:
  - **type** (string) (one of "local socket", "websocket", "ipv4", "ipv6", "torv2", "torv3"): Type of connection.
  - **address** (string, optional): Address in expected format for **type**.
  - **port** (u16, optional): Port number.

  If **type** is "local socket":
    - **socket** (string): Socket filename.

  If **type** is "websocket":
    - **subtype** (string): Type of address.

The following warnings may also be returned:

- **warning\_bitcoind\_sync**: Bitcoind is not up-to-date with network.
- **warning\_lightningd\_sync**: Lightningd is still loading latest blocks from bitcoind.

EXAMPLE JSON RESPONSE
---------------------

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
  "version": "v0.10.2",
  "blockheight": 724302,
  "network": "bitcoin",
  "msatoshi_fees_collected": 0,
  "fees_collected_msat": "0msat",
  "lightning-dir": "/media/vincent/Maxtor/C-lightning/node/bitcoin",
  "our_features": {
    "init": "8828226aa2",
    "node": "80008828226aa2",
    "channel": "",
    "invoice": "20024200"
  }
}
```

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters or some error happened during the command process.

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page,
but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel(7), lightning-listconfigs(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
