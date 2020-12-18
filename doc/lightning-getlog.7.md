lightning-getlog -- Command to show logs.
=========================================

SYNOPSIS
--------

**getlog** \[*level*\]

DESCRIPTION
-----------

The **getlog** the RPC command to show logs, with optional log *level*.

- *level*: Desired log level (*broken*, *unusual*, *info*, *debug*, or *io*) to filter on. The default is *info*.

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

On success, a object will be return with the following parameters:

- *created_at*: The UNIX timestamp of when the logging began as a float.
- *bytes_used*: Size in bytes of the log file.
- *bytes_max*: Maximum size in bytes of the log file.
- *log*: An array of objects where each element contains the following proprieties:
 - *type*: The log level of this entry. This property can have a value equal to `"SKIPPED"` to indicate the existence of omitted entries.
 - *time*: A floating point value that represents the time passed since *created_at*.
 - *source*: The file that emitted this log entry.
 - *log*: The log contents.
- *num_skipped*: An integer that it is present only if the log level is equal to SKIPPED.


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
