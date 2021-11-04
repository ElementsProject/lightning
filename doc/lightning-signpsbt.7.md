lightning-signpsbt -- Command to sign a wallet's inputs on a provided bitcoin transaction (PSBT).
=================================================================================================

SYNOPSIS
--------

**signpsbt** *psbt* [*signonly*]

DESCRIPTION
-----------

**signpsbt** is a low-level RPC command which signs a PSBT as defined by
BIP-174.

- *psbt*: A string that represents the PSBT value.
- *signonly*: An optional array of input numbers to sign.

By default, all known inputs are signed, and others ignored: with
*signonly*, only those inputs are signed, and an error is returned if
one of them cannot be signed.

Note that the command will fail if there are no inputs to sign, or
if the inputs to be signed were not previously reserved.


EXAMPLE JSON REQUEST
--------------------
```json
{
  "id": 82,
  "method": "signpsbt",
  "params": {
    "psbt": "some_psbt"
  }
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **signed_psbt** (string): The fully signed PSBT

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters, or there aren't wallet's inputs to sign, or we couldn't sign all of *signonly*, or inputs are not reserved.

EXAMPLE JSON RESPONSE
---------------------

```json
{
    "psbt": "some_psbt"
}
```

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

lightning-fundpsbt(7), lightning-sendpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:5f7bc2a5f8b6fe72bf70caa3ff14d6f1260c2d366becbc7798ee3bb0374e0b1b)
