lightning-getlog -- Command to show logs.
=========================================

SYNOPSIS
--------

**getlog** [*level*] 

DESCRIPTION
-----------

The **getlog** the RPC command to show logs, with optional log *level*.

- **level** (string, optional) (one of "broken", "unusual", "info", "debug", "io"): A string that represents the log level. The default is *info*.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:getlog#1",
  "method": "getlog",
  "params": {
    "level": "debug"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **created\_at** (string): UNIX timestamp with 9 decimal places, when logging was initialized.
- **bytes\_used** (u32): The number of bytes used by logging records.
- **bytes\_max** (u32): The bytes\_used values at which records will be trimmed .
- **log** (array of objects):
  - **type** (string) (one of "SKIPPED", "BROKEN", "UNUSUAL", "INFO", "DEBUG", "IO\_IN", "IO\_OUT")

  If **type** is "SKIPPED":
    - **num\_skipped** (u32): Number of unprinted log entries (deleted or below *level* parameter).

  If **type** is "BROKEN", "UNUSUAL", "INFO" or "DEBUG":
    - **time** (string): UNIX timestamp with 9 decimal places after **created\_at**.
    - **source** (string): The particular logbook this was found in.
    - **log** (string): The actual log message.
    - **node\_id** (pubkey, optional): The peer this is associated with.

  If **type** is "IO\_IN" or "IO\_OUT":
    - **time** (string): Seconds after **created\_at**, with 9 decimal places.
    - **source** (string): The particular logbook this was found in.
    - **log** (string): The associated log message.
    - **data** (hex): The IO which occurred.
    - **node\_id** (pubkey, optional): The peer this is associated with.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "created_at": "1598192543.820753463",
  "bytes_used": 89285843,
  "bytes_max": 104857600,
  "log": [
    {
      "type": "SKIPPED",
      "num_skipped": 45
    },
    {
      "type": "INFO",
      "time": "0.453627568",
      "source": "plugin-autopilot.py",
      "log": "RPCmethod'autopilot-run-once'doesnothaveadocstring."
    }
  ]
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
