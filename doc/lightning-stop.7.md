lightning-stop -- Command to shutdown the Core Lightning node.
==============================================================

SYNOPSIS
--------

**stop** 

DESCRIPTION
-----------

The **stop** is a RPC command to shut off the Core Lightning node.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:stop#1",
  "method": "stop",
  "params": {}
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **result** (string) (always "Shutdown complete") *(added v24.05)*

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "result": "Shutdown complete"
}
```

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page,
but many others did the hard work of actually implementing this rpc command.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
