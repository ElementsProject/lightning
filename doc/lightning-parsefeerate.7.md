lightning-parsefeerate -- Command for parsing a feerate string to a feerate
===========================================================================

SYNOPSIS
--------

**parsefeerate** *feerate\_str* 

DESCRIPTION
-----------

The **parsefeerate** command returns the current feerate for any valid *feerate\_str*. This is useful for finding the current feerate that a **fundpsbt** or **utxopsbt** command might use.

- **feerate\_str** (string): The feerate string to parse.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:parsefeerate#1",
  "method": "parsefeerate",
  "params": [
    "unilateral_close"
  ]
}
{
  "id": "example:parsefeerate#2",
  "method": "parsefeerate",
  "params": [
    "9999perkw"
  ]
}
{
  "id": "example:parsefeerate#3",
  "method": "parsefeerate",
  "params": [
    10000
  ]
}
{
  "id": "example:parsefeerate#4",
  "method": "parsefeerate",
  "params": [
    "urgent"
  ]
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **perkw** (u32, optional): Value of *feerate\_str* in kilosipa.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "perkw": 11000
}
{
  "perkw": 9999
}
{
  "perkw": 2500
}
{
  "perkw": 11000
}
```

ERRORS
------

The **parsefeerate** command will error if the *feerate\_str* format is not recognized.

- -32602: If the given parameters are wrong.

TRIVIA
------

In CLN we like to call the weight unit "sipa" in honor of Pieter Wuille, who uses the name "sipa" on IRC and elsewhere. Internally we call the *perkw* style as "feerate per kilosipa".

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
