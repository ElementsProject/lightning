lightning-signpsbt -- Command to sign a wallet's inputs on a provided bitcoin transaction (PSBT).
=================================================================================================

SYNOPSIS
--------

**signpsbt** *psbt*

DESCRIPTION
-----------

The **signpsbt** is a low-level RPC command which sign a PSBT.

- *psbt*: A string that rappresent the hexadecimal of the psbt.

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

On success, a object will be return with a string.

- *psbt*: A string that rappresent the hexadecimal dump of the psbt.

On failure, one of the following error codes may be returned:

- -32602. Error in given parameters or there aren't wallet's inputs to sign.

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
