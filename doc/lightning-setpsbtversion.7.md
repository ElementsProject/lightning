lightning-setpsbtversion -- Command for setting PSBT version
============================================================

SYNOPSIS
--------

**setpsbtversion** *psbt* *version* 

DESCRIPTION
-----------

The **setpsbtversion** RPC command converts the provided PSBT to the given version, and returns the base64 result of the conversion. Returns an error if version is invalid.

- **psbt** (string): The PSBT to change versions.
- **version** (u32): The version to set.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:setpsbtversion#1",
  "method": "setpsbtversion",
  "params": {
    "psbt": "cHNidP8BAAoCAAAAAAAAAAAAAA==",
    "version": "2"
  }
}
{
  "id": "example:setpsbtversion#2",
  "method": "setpsbtversion",
  "params": [
    "cHNidP8BAgQCAAAAAQMEbwAAAAEEAQABBQEBAQYBAwH7BAIAAAAAAQMIQEIPAAAAAAABBCJRIJd6ICNAQALFOMhoUHuSVSuzcaUdkDKlk4K+A+DR9+4uAA==",
    0
  ]
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **psbt** (string): A converted PSBT of the requested version.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "psbt": "cHNidP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA="
}
{
  "psbt": "cHNidP8BADUCAAAAAAFAQg8AAAAAACJRIJd6ICNAQALFOMhoUHuSVSuzcaUdkDKlk4K+A+DR9+4ubwAAAAAA"
}
```

ERRORS
------

The following error codes may occur:

- -32602: Parameter missed or malformed.

AUTHOR
------

Gregory Sanders <<gsanders87@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-fundpsbt(7), lightning-utxopsbt(7), lightning-signpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
