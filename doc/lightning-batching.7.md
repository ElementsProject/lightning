lightning-batching -- Command to allow database batching.
=========================================================

SYNOPSIS
--------

**batching** *enable*

DESCRIPTION
-----------

The **batching** RPC command allows (but does not guarantee!) database
commitments to be deferred when multiple commands are issued on this RPC
connection.  This is only useful if many commands are being given at once, in
which case it can offer a performance improvement (the cost being that if
there is a crash, it's unclear how many of the commands will have been
persisted).

*enable* is *true* to enable batching, *false* to disable it (the
default).

EXAMPLE JSON REQUEST
--------------------
```json
{
  "id": 82,
  "method": "batching",
  "params": {
    "enable": true
  }
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an empty object is returned.

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

AUTHOR
------

Rusty Russell <<rusty@blockstream.com>> wrote the initial version of this man page.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:41d0ca6a956520453538c8ad5c5afce681540f4ce26017570cdc2356c3aab599)
