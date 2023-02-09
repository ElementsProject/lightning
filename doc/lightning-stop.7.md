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
On success, returns a single element (string) (always "Shutdown complete")
[comment]: # (GENERATE-FROM-SCHEMA-END)

Once it has returned, the daemon has cleaned up completely, and if
desired may be restarted immediately.


AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.


RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:9ae0ce5a61e36232d45cf5d8bb6a84b7fdff4137fadfdcd5a35fdf995ce8ad84)
