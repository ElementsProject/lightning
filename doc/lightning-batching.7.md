lightning-batching -- Command to allow database batching.
=========================================================

SYNOPSIS
--------

**batching** *enable* 

DESCRIPTION
-----------

The **batching** RPC command allows (but does not guarantee!) database commitments to be deferred when multiple commands are issued on this RPC connection. This is only useful if many commands are being given at once, in which case it can offer a performance improvement (the cost being that if there is a crash, it's unclear how many of the commands will have been persisted).

- **enable** (boolean): Whether to enable or disable transaction batching. The default is False.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:batching#1",
  "method": "batching",
  "params": {
    "enable": true
  }
}
```

RETURN VALUE
------------

On success, an empty object is returned.

EXAMPLE JSON RESPONSE
---------------------

```json
{}
```

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

AUTHOR
------

Rusty Russell <<rusty@blockstream.com>> wrote the initial version of this man page.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
