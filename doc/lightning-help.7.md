lightning-help -- Command to return all information about RPC commands.
=======================================================================

SYNOPSIS
--------

**help** [*command*]

DESCRIPTION
-----------

The **help** is a RPC command which is possible consult all information about the RPC commands, or a specific command if *command* is given.

Note that the lightning-cli(1) tool will prefer to list a man page when a
specific *command* is specified, and will only return the JSON if the man
page is not found.

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

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **help** (array of objects):
  - **command** (string): the command
  - **category** (string): the category for this command (useful for grouping)
  - **description** (string): a one-line description of the purpose of this command
  - **verbose** (string): a full description of this command (including whether it's deprecated)

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

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

[comment]: # ( SHA256STAMP:2215b33f35ca1e21be55a68c24708a44d5e6525e9d681a92e3f43ffc0114bff4)
