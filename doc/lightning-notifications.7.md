lightning-notifications -- Command to set up notifications.
=========================================

SYNOPSIS
--------

**notifications** *enable*

DESCRIPTION
-----------

The **notifications** the RPC command enabled notifications for this JSON-RPC
connection.  By default (and for backwards-compatibility) notifications are
disabled.

Various commands, especially complex and slow ones, offer
notifications which indicate their progress.

- *enable*: *true* to enable notifications, *false* to disable them.

EXAMPLE JSON REQUEST
--------------------
```json
{
  "id": 82,
  "method": "notifications",
  "params": {
    "enable": true
  }
}
```

NOTIFICATIONS
-------------

Notifications are JSON-RPC objects without an *id* field.  *lightningd* sends
notifications (once enabled with this *notifications* command) with a *params*
*id* field indicating which command the notification refers to.

Implementations should ignore notifications without an *id* parameter, or
unknown *method*.

Common *method*s include:

- *message*: param *message*: a descriptional string indicating something
  which occurred relating to the command. Param *level* indicates the level,
  as per lightning-getlog(7): *info* and *debug* are typical.
- *progress*: param *num* and *total*, where *num* starts at 0 and is always
  less than *total*. Optional param *stage* with fields *num* and *total*,
  indicating what stage we are progressing through.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an empty object is returned.

[comment]: # (GENERATE-FROM-SCHEMA-END)

On success, if *enable* was *true*, notifications will be forwarded
from then on.

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

EXAMPLE NOTIFICATIONS
---------------------

```json
{
   "method": "message",
   "params": {
       "id": 83,
       "message": "This is a test message",
       "level": "DEBUG"
   }
}
```

```json
{
   "method": "progress",
   "params": {
       "id": 83,
       "num": 0,
       "total": 30
       "stage": {
           "num": 0,
           "total": 2
       }
   }
}
```

AUTHOR
------

Rusty Russell <<rusty@blockstream.com>> wrote the initial version of this man page.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:1a64fbaed63ffee21df3d46956a6dca193982b1b135a9b095e68652a720c77ac)
