lightning-ping -- Command to check if a node is up.
===================================================

SYNOPSIS
--------

**ping** *id* [*len*] [*pongbytes*] 

DESCRIPTION
-----------

The **ping** command checks if the node with *id* is ready to talk. It currently only works for peers we have a channel with.

- **id** (pubkey): The pubkey of the node to ping.
- **len** (u16, optional): The length of the ping. The default is 128.
- **pongbytes** (u16, optional): The length of the reply. A value of 65532 to 65535 means `don't reply`. The default is 128.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:ping#1",
  "method": "ping",
  "params": {
    "len": 128,
    "pongbytes": 128
  }
}
{
  "id": "example:ping#2",
  "method": "ping",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    "len": 1000,
    "pongbytes": 65535
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **totlen** (u16): The answer length of the reply message (including header: 0 means no reply expected).

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "totlen": 132
}
{
  "totlen": 0
}
```

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters or we're already waiting for a ping response from peer.

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page,
but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

lightning-connect(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
