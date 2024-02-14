lightning-notifications -- Command to set up notifications.
===========================================================

SYNOPSIS
--------

**notifications** *enable* 

DESCRIPTION
-----------

The **notifications** the RPC command enabled notifications for this JSON-RPC connection. By default (and for backwards-compatibility) notifications are disabled.

Various commands, especially complex and slow ones, offer notifications which indicate their progress.

- **enable** (boolean): Whether to enable or disable notifications.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:notifications#1",
  "method": "notifications",
  "params": {
    "enable": true
  }
}
{
  "id": "example:notifications#2",
  "method": "notifications",
  "params": {
    "enable": false
  }
}
```

NOTIFICATIONS
-------------

Notifications are JSON-RPC objects without an *id* field. *lightningd* sends notifications (once enabled with this *notifications* command) with a *params* *id* field indicating which command the notification refers to.

Implementations should ignore notifications without an *id* parameter, or unknown *method*.

Common *method*s include:
  *message*: param *message*: a descriptional string indicating something which occurred relating to the command. Param *level* indicates the level, as per lightning-getlog(7): *info* and *debug* are typical.
  *progress*: param *num* and *total*, where *num* starts at 0 and is always less than *total*. Optional param *stage* with fields *num* and *total*, indicating what stage we are progressing through.

RETURN VALUE
------------

On success, if *enable* was *true*, notifications will be forwarded from then on.

EXAMPLE JSON RESPONSE
---------------------

```json
{}
{}
```

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

EXAMPLE JSON NOTIFICATIONS
--------------------------

```json
{
  "method": "message",
  "params": {
    "id": 1,
    "message": "This is a test message",
    "level": "DEBUG"
  }
}
{
  "method": "progress",
  "params": {
    "id": 2,
    "num": 0,
    "total": 30,
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
