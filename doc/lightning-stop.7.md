lightning-stop -- Command to shut-off c-lightning node.
============================================================

SYNOPSIS
--------

**stop**

DESCRIPTION
-----------

The **stop** is a RPC command to shut-off the c-lightning node.

EXAMPLE JSON REQUEST
------------
```json
{
  "id": 82,
  "method": "stop",
  "params": {}
}
```

RETURN VALUE
------------

On success, the command will return a empty object.


AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.


RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
