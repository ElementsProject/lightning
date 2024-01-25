lightning-deprecations -- Command to enable/disable deprecated APIs
===================================================================

SYNOPSIS
--------

**deprecations** *enable*

DESCRIPTION
-----------

(Added *v24.02*)

The **deprecations** RPC command overrides the global `allow-deprecated-apis` flag for further RPC commands on this same connection.  In particular, setting *enable* to `false` will neither accept deprecated parameters or commands, nor output
deprecated fields.

This is equivalent to the config option `allow-deprecated-apis`, but can
be used on useful for developer testing to ensure you don't accidentally rely on
deprecated features.


EXAMPLE JSON REQUEST
--------------------
```json
{
  "id": 82,
  "method": "deprecations",
  "params": {
     "enable": false
  }
}
```

RETURN VALUE
------------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

AUTHOR
------

Rusty Russell <<rusty@blockstream.com>> wrote the initial version of this man page.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
