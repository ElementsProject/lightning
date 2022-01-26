lightning-getlog -- Command to show logs.
=========================================

SYNOPSIS
--------

**getlog** [*level*]

DESCRIPTION
-----------

The **getlog** the RPC command to show logs, with optional log *level*.

- *level*: A string that represents the log level (*broken*, *unusual*, *info*, *debug*, or *io*).  The default is *info*.

EXAMPLE JSON REQUEST
--------------------
```json
{
  "id": 82,
  "method": "getlog",
  "params": {
    "level": "debug"
  }
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **created_at** (string): UNIX timestamp with 9 decimal places, when logging was initialized
- **bytes_used** (u32): The number of bytes used by logging records
- **bytes_max** (u32): The bytes_used values at which records will be trimmed 
- **log** (array of objects):
  - **type** (string) (one of "SKIPPED", "BROKEN", "UNUSUAL", "INFO", "DEBUG", "IO_IN", "IO_OUT")

  If **type** is "SKIPPED":
    - **num_skipped** (u32): number of unprinted log entries (deleted or below *level* parameter)

  If **type** is "BROKEN", "UNUSUAL", "INFO" or "DEBUG":
    - **time** (string): UNIX timestamp with 9 decimal places after **created_at**
    - **source** (string): The particular logbook this was found in
    - **log** (string): The actual log message
    - **node_id** (pubkey, optional): The peer this is associated with

  If **type** is "IO_IN" or "IO_OUT":
    - **time** (string): Seconds after **created_at**, with 9 decimal places
    - **source** (string): The particular logbook this was found in
    - **log** (string): The associated log message
    - **data** (hex): The IO which occurred
    - **node_id** (pubkey, optional): The peer this is associated with

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

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
         "log": "RPC method 'autopilot-run-once' does not have a docstring."
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
[comment]: # ( SHA256STAMP:963fc75819ffb63271f25e31f30a6fe54457803d8bf296556589f76874fb39c0)
