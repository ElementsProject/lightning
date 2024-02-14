lightning-blacklistrune -- Command to prevent a rune from working
=================================================================

SYNOPSIS
--------

**blacklistrune** [*start* [*end*]]

DESCRIPTION
-----------

Command *added* in v23.08.

The **blacklistrune** RPC command allows you to effectively revoke the rune you have created (and any runes derived from that rune with additional restictions). Attempting to use these runes will be resulted in a `Blacklisted rune` error message.

Destroy a rune like in olden times with the **destroyrune** command.

All runes created by lightning have a unique sequential id within them and can be blacklisted in ranges for efficiency. The command always returns the blacklisted ranges on success. If no parameters are specified, no changes have been made. If start specified without end, that single rune is blacklisted. If end is also specified, every rune from start till end inclusive is blacklisted.

- **start** (u64, optional): First rune unique id to blacklist.
- **end** (u64, optional): Final rune unique id to blacklist (defaults to start).

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:blacklistrune#1",
  "method": "blacklistrune",
  "params": {
    "start": 2
  }
}
{
  "id": "example:blacklistrune#2",
  "method": "blacklistrune",
  "params": {
    "start": 5,
    "end": 7
  }
}
{
  "id": "example:blacklistrune#3",
  "method": "blacklistrune",
  "params": {
    "start": 3,
    "end": 4
  }
}
```

RETURN VALUE
------------

On success, an object containing **blacklist** is returned. It is an array of objects, where each object contains:

- **start** (u64): Unique id of first rune in this blacklist range.
- **end** (u64): Unique id of last rune in this blacklist range.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "blacklist": [
    {
      "start": 2,
      "end": 2
    }
  ]
}
{
  "blacklist": [
    {
      "start": 2,
      "end": 2
    },
    {
      "start": 5,
      "end": 7
    }
  ]
}
{
  "blacklist": [
    {
      "start": 2,
      "end": 7
    }
  ]
}
```

AUTHOR
------

Shahana Farooqui <<sfarooqui@blockstream.com>> is mainly responsible.

SEE ALSO
--------

lightning-commando-blacklist(7), lightning-showrunes(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
