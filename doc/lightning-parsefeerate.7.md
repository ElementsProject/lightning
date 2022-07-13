lightning-parsefeerate -- Command for parsing a feerate string to a feerate
===========================================================================

SYNOPSIS
--------

**parsefeerate** *feerate_str*

DESCRIPTION
-----------

The **parsefeerate** command returns the current feerate for any valid
*feerate_str*. This is useful for finding the current feerate that a
**fundpsbt** or **utxopsbt** command might use.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **perkw** (u32, optional): Value of *feerate_str* in kilosipa

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The **parsefeerate** command will error if the *feerate_str* format is
not recognized.

- -32602: If the given parameters are wrong.

TRIVIA
------

In CLN we like to call the weight unit "sipa"
in honor of Pieter Wuille,
who uses the name "sipa" on IRC and elsewhere.
Internally we call the *perkw* style as "feerate per kilosipa".

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:f3498aa6f16d5be0a49896ae67144558df1baa223ac396a90ddf2d89a42ff395)
