lightning-ping -- Command to check if a node is up.
============================================================

SYNOPSIS
--------

**ping** *id* \[len\] \[pongbytes\]

DESCRIPTION
-----------

The **ping** command check if the node with id is ready to talk. It accept the following parameter:

- *id*: A string that rappresent the node id;
- *len*: A integer that rappresent the lenght of {...}, by default is 128;
- *pongbytes*: An integer that rappresent the lenght of {}, by default is 128.

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

- *totlen*: A string that rappresent the answer lenght of {}.

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters or unknow peer.

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
