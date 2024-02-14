lightning-connect -- Command for connecting to another lightning node
=====================================================================

SYNOPSIS
--------

**connect** *id* [*host*] [*port*] 

DESCRIPTION
-----------

The **connect** RPC command establishes a new connection with another node in the Lightning Network.

Connecting to a node is just the first step in opening a channel with another node. Once the peer is connected a channel can be opened with lightning-fundchannel(7).

If there are active channels with the peer, **connect** returns once all the subdaemons are in place to handle the channels, not just once it's connected.

- **id** (string): The target node's public key. As a convenience, *id* may be of the form *id@host* or *id@host:port*. In this case, the *host* and *port* parameters must be omitted. This can fail if your C-lightning node is a fresh install that has not connected to any peers yet (your node has no gossip yet), or if the target *id* is a fresh install that has no channels yet (nobody will gossip about a node until it has one published channel).
- **host** (string, optional): The peer's hostname or IP address. If *host* is not specified (or doesn't work), the connection will be attempted to an IP belonging to *id* obtained through gossip with other already connected peers. If *host* begins with a `/` it is interpreted as a local path and the connection will be made to that local socket (see **bind-addr** in lightningd-config(5)).
- **port** (u16, optional): The peer's port number. If not specified, the *port* depends on the current network:
     * bitcoin **mainnet**: 9735.
     * bitcoin **testnet**: 19735.
     * bitcoin **signet**: 39735.
     * bitcoin **regtest**: 19846.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:connect#1",
  "method": "connect",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    "host": "localhost",
    "port": 44619
  }
}
{
  "id": "example:connect#2",
  "method": "connect",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    "host": "127.0.0.1",
    "port": 42839
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **id** (pubkey): The peer we connected to.
- **features** (hex): BOLT 9 features bitmap offered by peer.
- **direction** (string) (one of "in", "out"): Whether they initiated connection or we did.
- **address** (object): Address information (mainly useful if **direction** is *out*).:
  - **type** (string) (one of "local socket", "ipv4", "ipv6", "torv2", "torv3"): Type of connection (*torv2*/*torv3* only if **direction** is *out*).

  If **type** is "local socket":
    - **socket** (string): Socket filename.

  If **type** is "ipv4", "ipv6", "torv2" or "torv3":
    - **address** (string): Address in expected format for **type**.
    - **port** (u16): Port number.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
  "features": "08a0000a0a69a2",
  "direction": "out",
  "address": {
    "type": "ipv4",
    "address": "127.0.0.1",
    "port": 44619
  }
}
{
  "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
  "features": "08a0000a8a5961",
  "direction": "out",
  "address": {
    "type": "ipv4",
    "address": "127.0.0.1",
    "port": 42839
  }
}
```

ERRORS
------

On failure, one of the following errors will be returned:

- 400: Unable to connect, no address known for peer
- 401: If some addresses are known but connecting to all of them failed, the message will contain details about the failures
- 402: If the peer disconnected while we were connecting
- -32602: If the given parameters are wrong

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible. Felix <<fixone@gmail.com>> is the original author of this manpage.

SEE ALSO
--------

lightning-fundchannel(7), lightning-listpeers(7), lightning-listchannels(7), lightning-disconnect(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
