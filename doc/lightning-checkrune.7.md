lightning-checkrune -- Command to Validate Rune
================================================

SYNOPSIS
--------

**checkrune** [*nodeid*], [*rune*], [*method*] [*params*]

DESCRIPTION
-----------

The **checkrune** RPC command checks the validity/authorization rights of specified rune for the given nodeid, method, and params.

It will return {valid: true} if the rune is authorized otherwise returns error message.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **valid** (boolean): true if the rune is valid

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Shahana Farooqui <<sfarooqui@blockstream.com>> is mainly responsible 
for consolidating logic from commando.

SEE ALSO
--------

lightning-createrune(7), lightning-blacklistrune(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:977acf366f8fde1411f2c78d072b34b38b456e95381a6bce8fe6855a2d91434a)
