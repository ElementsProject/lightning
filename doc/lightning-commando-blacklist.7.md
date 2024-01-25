lightning-commando-blacklist -- Command to prevent a rune from working
======================================================================

SYNOPSIS
--------

**commando-blacklist** [*start* [*end*]]

DESCRIPTION
-----------

The **commando-blacklist** RPC command allows you to effectively revoke the rune you have created (and any runes derived from that rune with additional restictions). Attempting to use these runes will be resulted in a `Blacklisted rune` error message.

All runes created by commando have a unique sequential id within them and can be blacklisted in ranges for efficiency. The command always returns the blacklisted ranges on success. If no parameters are specified, no changes have been made. If start specified without end, that single rune is blacklisted. If end is also specified, every rune from start till end inclusive is blacklisted.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **blacklist** is returned.  It is an array of objects, where each object contains:

- **start** (u64): Unique id of first rune in this blacklist range
- **end** (u64): Unique id of last rune in this blacklist range

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Shahana Farooqui <<sfarooqui@blockstream.com>> is mainly responsible.

SEE ALSO
--------

lightning-commando-listrunes(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:7f9e7ab72e0e8d6e7cc59c560a274ffcfd5d257c73e37866d05ffa74d587fb3f)
