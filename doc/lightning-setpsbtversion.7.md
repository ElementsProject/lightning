lightning-setpsbtversion -- Command for setting PSBT version
============================================================

SYNOPSIS
--------

**setpsbtversion** *psbt* *version*

DESCRIPTION
-----------

The **setpsbtversion** RPC command converts the provided PSBT to the given version, and returns the base64 result of the conversion. Returns an error if version is invalid.

EXAMPLE JSON REQUEST
------------

```json
{
  "id": 82,
  "method": "setpsbtversion",
  "params": {
    "psbt": "cHNidP8BAAoCAAAAAAAAAAAAAA==",
    "version": "2"
  }
}
```

RETURN VALUE
------------

If successful the command returns a converted PSBT of the requested version.

ERRORS
------

The following error codes may occur:

- 32602: Parameter missed or malformed.

EXAMPLE JSON RESPONSE
-----

```json
{
    "psbt": "cHNidP8BAgQCAAAAAQQBAAEFAQABBgEDAfsEAgAAAAA="
}
```

AUTHOR
------

Gregory Sanders <<gsanders87@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-fundpsbt(7), lightning-utxopsbt(7), lightning-signpsbt(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
