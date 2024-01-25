lightning-sendpsbt -- Command to finalize, extract and send a partially signed bitcoin transaction (PSBT).
==========================================================================================================

SYNOPSIS
--------

**sendpsbt** *psbt* [*reserve*]

DESCRIPTION
-----------

The **sendpsbt** is a low-level RPC command which sends a fully-signed PSBT.

- *psbt*: A string that represents psbt value.
- *reserve*: an optional number of blocks to increase reservation of any of our inputs by; default is 72.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": 82,
  "method": "sendpsbt",
  "params": {
    "psbt": "some_psbt"
  }
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **tx** (hex): The raw transaction which was sent
- **txid** (txid): The txid of the **tx**

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters or some error happened during the command process.

EXAMPLE JSON RESPONSE
---------------------

```json
{
    "txid": "05985072bbe20747325e69a159fe08176cc1bbc96d25e8848edad2dddc1165d0",
    "tx": "02000000027032912651fc25a3e0893acd5f9640598707e2dfef92143bb5a4020e335442800100000017160014a5f48b9aa3cb8ca6cc1040c11e386745bb4dc932ffffffffd229a4b4f78638ebcac10a68b0561585a5d6e4d3b769ad0a909e9b9afaeae24e00000000171600145c83da9b685f9142016c6f5eb5f98a45cfa6f686ffffffff01915a01000000000017a9143a4dfd59e781f9c3018e7d0a9b7a26d58f8d22bf8700000000",
}
```

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

lightning-fundpsbt(7), lightning-signpsbt(7), lightning-listtransactions(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:ba123ea4052af7850655f99ee85ed42c0254d7c15ba3861df0574fd58e4d8355)
