lightning-signpsbt -- Command to sign a wallet's inputs on a provided bitcoin transaction (PSBT).
=================================================================================================

SYNOPSIS
--------

**signpsbt** *psbt* [*signonly*]

DESCRIPTION
-----------

**signpsbt** is a low-level RPC command which signs a PSBT as defined by
BIP-174.

- *psbt*: A base64-encoded string of the PSBT.
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
    "psbt": "cHNidP8BAHEBAAAAAZ+dQXWMU0UUQW5guh1gAqRk6qV1EfswIxDz/l6pI4BYAAAAAAD/////AuQGAAAAAAAAFgAUNiXEouqXR2CoFjaP0V3ncVlEdue0RKASAAAAABYAFKswhKbTAJ6fHwhnBttaS62vUkitAAAAAAAAAAA="
  }
}
```

RETURN VALUE
------------

On success, a object will be returned with a string.

- *psbt*: A base64-PSBT with the specified inputs signed.

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters, or there aren't wallet's inputs to sign, or we couldn't sign all of *signonly*, or inputs are not reserved.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "psbt": "cHNidP8BAHQBAAAAAcEKbzkcVvItfXURLb6PtIlar9N9jVKBZuxm34PsxGxgAAAAAAD/////AuQGAAAAAAAAFgAUNiXEouqXR2CoFjaP0V3ncVlEdueU1wUqAQAAABl2qRRxMMXp8bpyw7zzcTTnkjHukFng14isAAAAAAABAIUCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wNSAQH/////AgDyBSoBAAAAF6kU8Lg4vWyj9numjGv33kmU8Xj7+XiHAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkAAAAAAQEgAPIFKgEAAAAXqRTwuDi9bKP2e6aMa/feSZTxePv5eIcBBxcWABT3We/RPg4o3h4maqWGMKzDVE01JQEIawJHMEQCIDFf4Y8vEDgQEkYVPOMyZas7eDpL1In8OSqKhrYftufXAiAdGOETFcD4Ge/y5e9BAwJZYueRvfUnmCzFQhmA5F9oOwEhA5EQC8GjcXM6YayF40YJviaUnNI2O7BMaUHZOWS7qJAoAAAiAgMAI5tx4a99gMvc9XHlmZjIpfz56hXBUrCTKexXf1CyURDRNMcTAAAAgAAAAIAsAACAAA=="
}
```

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this RPC command.

SEE ALSO
--------

lightning-fundpsbt(7), lightning-sendpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
