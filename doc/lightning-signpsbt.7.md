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
- *signonly*: An an array of input numbers to sign.
- *utxo\_string*: An an array of outputs to sign.
- *unsafe\_sign\_all*: A flag to recklessly sign all reserved inputs.

Specify which inputs to sign by either an array of input indices to sign with
*sigonly* or a *utxo\_string*.

*utxo\_string* is in the format of a txid and outnum seperated by a colon.
Multiple utxos can be added by putting a comma inbetween entries. As such:
txid:outnum,txid:outnum... This is the same format returned by fundpsbt.

An error is returned if one of them cannot be signed.

Note that the command will fail if there are no inputs to sign, or
if the inputs to be signed were not previously reserved.


EXAMPLE JSON REQUEST
--------------------
```json
{
  "id": 82,
  "method": "signpsbt",
  "params": {
    "psbt": "some_psbt",
    "utxo_string": "txid:outnum,txid:outnum"
  }
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **signed\_psbt** (string): The fully signed PSBT

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

[comment]: # ( SHA256STAMP:d016f1aab17aab7a4d2f127cbab4af79a3b43f35a5e6f893ddd355110520e111)
