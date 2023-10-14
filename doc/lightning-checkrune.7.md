lightning-checkrune -- Command to Validate Rune
================================================

SYNOPSIS
--------

**checkrune** *rune* [*nodeid*] [*method*] [*params*]

DESCRIPTION
-----------

The **checkrune** RPC command checks the validity/authorization rights of specified rune for the given nodeid, method, and params.

If successful, the rune "usage" counter (used for ratelimiting) is incremented.

See lightning-createrune(7) for the fields in the rune which are checked.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **valid** (boolean): true if the rune is valid

[comment]: # (GENERATE-FROM-SCHEMA-END)

The following error codes may occur:

- RUNE\_NOT\_AUTHORIZED (1501): rune is not for this node (or perhaps completely invalid)
- RUNE\_NOT\_PERMITTED (1502): rune does not allow this usage (includes a detailed reason why)
- RUNE\_BLACKLISTED (1503): rune has been explicitly blacklisted.

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
