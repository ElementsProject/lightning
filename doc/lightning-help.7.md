lightning-help -- Command to return all information about RPC commands.
=======================================================================

SYNOPSIS
--------

**help**

DESCRIPTION
-----------

The **help** is a RPC command which is possible consult all information about the RPC commands.

EXAMPLE JSON REQUEST
--------------------
```json
{
  "id": 82,
  "method": "help",
  "params": {}
}
```

RETURN VALUE
------------

On success, a object will be return with the following proprieties:

- *command*: A string that rappresent the stucture of the command.
- *category*: A string that rappresent the category.
- *description*: A string that rappresent the description.
- *verbose*: A string that rappresent the verbode description.

On failure, one of the following error codes may be returned:

- -32602. Error in given parameters.

EXAMPLE JSON RESPONSE
---------------------

```json
{
    "help": [
      {
        "command": "autocleaninvoice [cycle_seconds] [expired_by]",
        "category": "plugin",
        "description": "Set up autoclean of expired invoices. ",
        "verbose": "Perform cleanup every {cycle_seconds} (default 3600), or disable autoclean if 0. Clean up expired invoices that have expired for {expired_by} seconds (default 86400). "
      }
    ]
}
```

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
