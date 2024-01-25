lightning-parsefeerate -- Command for parsing a feerate string to a feerate
===========================================================================

SYNOPSIS
--------

**parsefeerate** *feerate\_str*

DESCRIPTION
-----------

The **parsefeerate** command returns the current feerate for any valid
*feerate\_str*. This is useful for finding the current feerate that a
**fundpsbt** or **utxopsbt** command might use.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **perkw** (u32, optional): Value of *feerate\_str* in kilosipa

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The **parsefeerate** command will error if the *feerate\_str* format is
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

[comment]: # ( SHA256STAMP:01ed00df0f944625c827aa538c173e988a7ba7cebbddb16f5a392206a296fbd3)
