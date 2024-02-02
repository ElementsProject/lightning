lightning-ping -- Command to check if a node is up.
============================================================

SYNOPSIS
--------

**ping** *id* [*len*] [*pongbytes*]

DESCRIPTION
-----------

The **ping** command checks if the node with *id* is ready to talk.
It currently only works for peers we have a channel with.

EXAMPLE JSON REQUEST
------------

```json
{
  "id": 82,
  "method": "ping",
  "params": {
    "len": 128,
    "pongbytes": 128
  }
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **totlen** (u16): the answer length of the reply message (including header: 0 means no reply expected)

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters or we're already waiting for a ping response from peer.

EXAMPLE JSON RESPONSE
-----

```json
{
   "totlen": 132
}

```


AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

lightning-connect(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:3d65bfe95b32d6f1229fcf9215045516ff04e670de8ba0485e585d699e1b1f71)
