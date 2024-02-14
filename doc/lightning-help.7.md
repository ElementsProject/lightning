lightning-help -- Command to return all information about RPC commands.
=======================================================================

SYNOPSIS
--------

**help** [*command*] 

DESCRIPTION
-----------

The **help** is a RPC command which is possible consult all information about the RPC commands, or a specific command if *command* is given.

Note that the lightning-cli(1) tool will prefer to list a man page when a specific *command* is specified, and will only return the JSON if the man page is not found.

- **command** (string, optional): Command to get information about.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:help#1",
  "method": "help",
  "params": {
    "command": "pay"
  }
}
{
  "id": "example:help#2",
  "method": "help",
  "params": {
    "command": "dev"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **help** (array of objects):
  - **command** (string): The command.
  - **category** (string): The category for this command (useful for grouping).
  - **description** (string): A one-line description of the purpose of this command.
  - **verbose** (string): A full description of this command (including whether it's deprecated).
- **format-hint** (string, optional) (always "simple"): Prints the help in human-readable flat form.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "help": [
    {
      "command": "pay bolt11 [amount_msat] [label] [riskfactor] [maxfeepercent] [retry_for] [maxdelay] [exemptfee] [localinvreqid] [exclude] [maxfee] [description] [dev_use_shadow]",
      "category": "plugin",
      "description": "Send payment specified by {bolt11}",
      "verbose": "Attempt to pay the {bolt11} invoice."
    }
  ],
  "format-hint": "simple"
}
{
  "help": [
    {
      "command": "dev subcommand=crash|rhash|slowcmd",
      "category": "developer",
      "description": "Developer command test multiplexer",
      "verbose": "dev rhash {secret}\n\tShow SHA256 of {secret}\ndev crash\n\tCrash lightningd by calling fatal()\ndev slowcmd {msec}\n\tTorture test for slow commands, optional {msec}\n"
    }
  ],
  "format-hint": "simple"
}
```

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page,
but many others did the hard work of actually implementing this rpc command.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
