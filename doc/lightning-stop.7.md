lightning-stop -- Command to shutdown the Core Lightning node.
==============================================================

SYNOPSIS
--------

**stop**

DESCRIPTION
-----------

The **stop** is a RPC command to shut off the Core Lightning node.

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

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **result** (string) (always "Shutdown complete") *(added v24.05)*

[comment]: # (GENERATE-FROM-SCHEMA-END)

Once it has returned, the daemon has cleaned up completely, and if
desired may be restarted immediately.


AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.


RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:91bba4770ed15de26de26d1fa380817a0f323293aae7a95eda835b7d566aad85)
