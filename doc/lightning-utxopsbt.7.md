lightning-utxopsbt -- Command to populate PSBT inputs from given UTXOs
======================================================================

SYNOPSIS
--------

**utxopsbt** *satoshi* *feerate* *startweight* *utxos* [*reserve*] [*reservedok*] [*locktime*] [*min\_witness\_weight*] [*excess\_as\_change*] [*opening\_anchor\_channel*] 

DESCRIPTION
-----------

*utxopsbt* is a low-level RPC command which creates a PSBT using unreserved inputs in the wallet, optionally reserving them as well.

It deliberately mirrors the parameters and output of lightning-fundpsbt(7) except instead of an optional *minconf* parameter to select unreserved outputs from the wallet, it takes a compulsory list of outputs to use.

- **satoshi** (msat\_or\_all): The minimum satoshi value of the output(s) needed (or the string `all` meaning use all unreserved inputs). If a value, it can be a whole number, a whole number ending in *sat*, a whole number ending in *000msat*, or a number with 1 to 8 decimal places ending in *btc*.
- **feerate** (feerate): Used for the transaction as initial feerate. The default is *normal*.
- **startweight** (u32): The weight of the transaction before *fundpsbt* has added any inputs.
- **utxos** (array of outpoints): An array of `txid:vout`, each of which must be reserved or available.:
  - (outpoint, optional)
- **reserve** (u32, optional): If not zero, then *reserveinputs* is called (successfully, with *exclusive* true) on the returned PSBT for this number of blocks. The default is 72 blocks.
- **reservedok** (boolean, optional): If set to true, it will also fail if any of the *utxos* are already reserved. The default is false.
- **locktime** (u32, optional): If not set, it is set to a recent block height.
- **min\_witness\_weight** (u32, optional): Minimum weight to use for a UTXO's witness. If the actual witness weight is greater than the provided minimum, the actual witness weight will be used.
- **excess\_as\_change** (boolean, optional): Flag to add a change output for the excess sats.
- **opening\_anchor\_channel** (boolean, optional): To signel that it needs emergency reserve for anchors so that we can lowball our commitment tx fees, and min-emergency-msat for reserving some sats for closing anchor channels. *(added v23.08)*

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:utxopsbt#1",
  "method": "utxopsbt",
  "params": {
    "satoshi": 0,
    "feerate": "253perkw",
    "startweight": 0,
    "utxos": [
      "d82a99192fb333106ea8d08f5231ed45f2ed5b1ef9eb81b0fef8f9ea354d2637:1"
    ],
    "reserve": 0,
    "reservedok": true,
    "locktime": null,
    "min_witness_weight": null,
    "excess_as_change": false
  }
}
{
  "id": "example:utxopsbt#2",
  "method": "utxopsbt",
  "params": {
    "satoshi": 1000000,
    "feerate": "7500perkw",
    "startweight": 0,
    "utxos": [
      "2fc3b9f8d4aed120f6d9a6f206f07c35ef4d518ec0305d1d974873d256e38ca7:1",
      "2f669f6a605ee5c7ddd2abb753bc64b1a90bd1b7448264f5d78a7ca823c00a1b:1"
    ],
    "reserve": null,
    "reservedok": true,
    "locktime": null,
    "min_witness_weight": null,
    "excess_as_change": false
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **psbt** (string): Unsigned PSBT which fulfills the parameters given.
- **feerate\_per\_kw** (u32): The feerate used to create the PSBT, in satoshis-per-kiloweight.
- **estimated\_final\_weight** (u32): The estimated weight of the transaction once fully signed.
- **excess\_msat** (msat): The amount above *satoshi* which is available. This could be zero, or dust; it will be zero if *change\_outnum* is also returned.
- **change\_outnum** (u32, optional): The 0-based output number where change was placed (only if parameter *excess\_as\_change* was true and there was sufficient funds).
- **reservations** (array of objects, optional): If *reserve* was true or a non-zero number, just as per lightning- reserveinputs(7).:
  - **txid** (txid): The txid of the transaction.
  - **vout** (u32): The 0-based output number.
  - **was\_reserved** (boolean): Whether this output was previously reserved.
  - **reserved** (boolean) (always *true*): Whether this output is now reserved.
  - **reserved\_to\_block** (u32): The blockheight the reservation will expire.

On success, returns the *psbt* it created, containing the inputs, *feerate\_per\_kw* showing the exact numeric feerate it used, *estimated\_final\_weight* for the estimated weight of the transaction once fully signed, and *excess\_msat* containing the amount above *satoshi* which is available. This could be zero, or dust. If *satoshi* was `all`, then *excess\_msat* is the entire amount once fees are subtracted for the weights of the inputs and *startweight*.

If *reserve* was *true* or a non-zero number, then a *reservations* array is returned, exactly like *reserveinputs*.

If *excess\_as\_change* is true and the excess is enough to cover an additional output above the `dust_limit`, then an output is added to the PSBT for the excess amount. The *excess\_msat* will be zero. A *change\_outnum* will be returned with the index of the change output.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "psbt": "cHNidP8BADMCAAAAATcmTTXq+fj+sIHr+R5b7fJF7TFSj9CobhAzsy8ZmSrYAQAAAAD9////AGYAAAAAAQDeAgAAAAABAWQACJva49ga8OCYXvPRWQRhoXndrJykwjgXbwT251dEAAAAAAD9////AiOI9ikBAAAAFgAU3gClv/YpAKRpfDuiFu6mIL2E4+5QaQ8AAAAAABYAFAH62Qq81maX4lkhZHIt5KlevuFlAkcwRAIgUXIQFs7oRkorVThUn3sLj7WI7g8c8RHai4ChoCvIkWsCICp1CqHl4BlMJCKFHRWHXhhekaj0r1EFSNrh8UnvysQPASEDqHIAEdaH3H6pb3VJzbJNDG4lL8PTfsheL+h2p6baK3JlAAAAAQEfUGkPAAAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQA=",
  "feerate_per_kw": 253,
  "estimated_final_weight": 271,
  "excess_msat": 1009932000
}
{
  "psbt": "cHNidP8BAFwCAAAAAqeM41bSc0iXHV0wwI5RTe81fPAG8qbZ9iDRrtT4ucMvAQAAAAD9////GwrAI6h8itf1ZIJEt9ELqbFkvFO3q9Ldx+VeYGqfZi8BAAAAAP3///8AZgAAAAABAN4CAAAAAAEBEaK0TQ97IsrzuO1gLt+vYbvLBG90NrCOZp7SCgrRknYAAAAAAP3///8CM6/2KQEAAAAWABQ1B/KkIVbg7yFRcCEN/VOptfOX/EBCDwAAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WUCRzBEAiA1oI1us81XEa/DRlvcP2qnbWLsV5pZcRfvj9MLyT202gIgb7noMqHYWMmm7H7VNEfWa29jjtuV9yrrSc9ui11ECQ0BIQKhZOHR4gFKMu2EKKgZ/7qnhzq9PvhtnAW2sxPZ4c9RIWUAAAABAR9AQg8AAAAAABYAFAH62Qq81maX4lkhZHIt5KlevuFlAAEA3gIAAAAAAQGnjONW0nNIlx1dMMCOUU3vNXzwBvKm2fYg0a7U+LnDLwAAAAAA/f///wJmbOcpAQAAABYAFOwPo5eUrDF7UgZBFQLRHOeX6PiGQEIPAAAAAAAWABTCzKsXHCpb6dq1LsQbglhjAkxUZgJHMEQCICgjGlauGj2eiMS4MWUK6zAWqMe1OuidQR+Hy9ZgSTuzAiA8JTb9OrLqS3hiWtT+TQ/NBsKJ2hhHLDaKUUNdgi4OkAEhA9g3oH5ejmGIqUY2ZWxc8YWF2+T+XpE/6oC40Cx3+e97ZQAAAAEBH0BCDwAAAAAAFgAUwsyrFxwqW+natS7EG4JYYwJMVGYA",
  "feerate_per_kw": 7500,
  "estimated_final_weight": 542,
  "excess_msat": 995935000,
  "reservations": [
    {
      "txid": "2fc3b9f8d4aed120f6d9a6f206f07c35ef4d518ec0305d1d974873d256e38ca7",
      "vout": 1,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    },
    {
      "txid": "2f669f6a605ee5c7ddd2abb753bc64b1a90bd1b7448264f5d78a7ca823c00a1b",
      "vout": 1,
      "was_reserved": true,
      "reserved": true,
      "reserved_to_block": 246
    }
  ]
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 301: Insufficient UTXOs to meet *satoshi* value.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-fundpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
