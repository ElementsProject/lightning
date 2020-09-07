lightning-ping -- Command to check if a node is up.
============================================================

SYNOPSIS
--------

**ping** *id* \[len\] \[pongbytes\]

DESCRIPTION
-----------

The **ping** command checks if the node with *id* is ready to talk. It accepts the following parameters:

- *id*: A string that represents the node id;
- *len*: A integer that represents the length of the ping (default 128);
- *pongbytes*: An integer that represents the length of the reply (default 128).

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

On success, the command will return an object with a single string.

- *totlen*: A string that represents the answer length of the reply message (including header)

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters or unknown peer.

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
