lightning-getlog -- Command to show logs.
=========================================

SYNOPSIS
--------

**getlog** \[level\]

DESCRIPTION
-----------

The **getlog** the RPC command to show logs, with optional log *level*.

- *level*: A string that rappresent the log level (info, unusual, debug, io).

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

- *created_at*: An floating point value that rappresent the {}. 
- *bytes_used*: A string that rappresent the dimension in bytes of the log file.
- *bytes_max*: An integer that rappresent the max dimension in bytes of log file.
- *log*: An array of object where each elements contains the following proprieties:
 - *type*: A string that rappresent the log level. The propriety can have an value equal to SKIPPED.
 - *time*: A floating point value that rappresent the time.
 - *source*: A string that rappresent the source of line.
 - *log*: A string that rappresent the content of line.
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
