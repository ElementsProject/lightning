lightning-commando-blacklist -- Command to prevent a rune from working
======================================================================

SYNOPSIS
--------

**commando-blacklist** [*start* [*end*]]

DESCRIPTION
-----------

Command **deprecated in v23.08, removed after v24.08**.

Command *added* in v23.05.

The **commando-blacklist** RPC command allows you to effectively revoke the rune you have created (and any runes derived from that rune with additional restictions). Attempting to use these runes will be resulted in a `Blacklisted rune` error message.

All runes created by commando have a unique sequential id within them and can be blacklisted in ranges for efficiency. The command always returns the blacklisted ranges on success. If no parameters are specified, no changes have been made. If start specified without end, that single rune is blacklisted. If end is also specified, every rune from start till end inclusive is blacklisted.

- **start** (u64, optional): First rune unique id to blacklist.
- **end** (u64, optional): Final rune unique id to blacklist (defaults to start).

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:commando-blacklist#1",
  "method": "commando-blacklist",
  "params": {
    "start": 2
  }
}
{
  "id": "example:commando-blacklist#2",
  "method": "commando-blacklist",
  "params": {
    "start": 5,
    "end": 7
  }
}
{
  "id": "example:commando-blacklist#3",
  "method": "commando-blacklist",
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

lightning-commando-listrunes(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
