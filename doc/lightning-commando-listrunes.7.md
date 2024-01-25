lightning-commando-listrunes -- Command to list previously generated runes
==========================================================================

SYNOPSIS
--------

**commando-listrunes** [*rune*]

DESCRIPTION
-----------

The **commando-listrunes** RPC command either lists runes that we stored as we generate them (see lightning-commando-rune(7)) or decodes the rune given on the command line. 

NOTE: Runes generated prior to v23.05 were not stored, so will not appear in this list.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **runes** is returned.  It is an array of objects, where each object contains:

- **rune** (string): Base64 encoded rune
- **unique\_id** (string): Unique id assigned when the rune was generated; this is always a u64 for commando runes
- **restrictions** (array of objects): The restrictions on what commands this rune can authorize:
  - **alternatives** (array of objects):
    - **fieldname** (string): The field this restriction applies to; see commando-rune(7)
    - **value** (string): The value accepted for this field
    - **condition** (string): The way to compare fieldname and value
    - **english** (string): English readable description of this alternative
  - **english** (string): English readable summary of alternatives above
- **restrictions\_as\_english** (string): English readable description of the restrictions array above
- **stored** (boolean, optional): This is false if the rune does not appear in our datastore (only possible when `rune` is specified) (always *false*)
- **blacklisted** (boolean, optional): The rune has been blacklisted; see commando-blacklist(7) (always *true*)
- **last\_used** (number, optional): The last time this rune was successfully used *(added 23.11)*
- **our\_rune** (boolean, optional): This is not a rune for this node (only possible when `rune` is specified) (always *false*)

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Shahana Farooqui <<sfarooqui@blockstream.com>> is mainly responsible.

SEE ALSO
--------

lightning-commando-rune(7), lightning-commando-blacklist(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:f951001acafe71d2ab6d95367bd122067f449af71e755672e44e719fc5a8c1fa)
