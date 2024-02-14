lightning-fundpsbt -- Command to populate PSBT inputs from the wallet
=====================================================================

SYNOPSIS
--------

**fundpsbt** *satoshi* *feerate* *startweight* [*minconf*] [*reserve*] [*locktime*] [*min\_witness\_weight*] [*excess\_as\_change*] [*nonwrapped*] [*opening\_anchor\_channel*] 

DESCRIPTION
-----------

`fundpsbt` is a low-level RPC command which creates a PSBT using unreserved inputs in the wallet, optionally reserving them as well.

- **satoshi** (msat\_or\_all): The minimum satoshi value of the output(s) needed (or the string `all` meaning use all unreserved inputs). If a value, it can be a whole number, a whole number ending in *sat*, a whole number ending in *000msat*, or a number with 1 to 8 decimal places ending in *btc*.
- **feerate** (feerate): Used for the transaction as initial feerate. The default is *normal*.
- **startweight** (u32): The weight of the transaction before *fundpsbt* has added any inputs.
- **minconf** (u32, optional): The minimum number of confirmations that used outputs should have. The default is 1.
- **reserve** (u32, optional): If not zero, then *reserveinputs* is called (successfully, with *exclusive* true) on the returned PSBT for this number of blocks. The default is 72 blocks.
- **locktime** (u32, optional): The locktime of the transaction. if not set, it is set to a recent block height.
- **min\_witness\_weight** (u32, optional): Minimum weight to use for a UTXO's witness. If the actual witness weight is greater than the provided minimum, the actual witness weight will be used.
- **excess\_as\_change** (boolean, optional): Flag to add a change output for the excess sats.
- **nonwrapped** (boolean, optional): To signal to filter out any p2sh-wrapped inputs from funding this PSBT. *(added v23.02)*
- **opening\_anchor\_channel** (boolean, optional): To signel that it needs emergency reserve for anchors so that we can lowball our commitment tx fees, and min-emergency-msat for reserving some sats for closing anchor channels. *(added v23.08)*

EXAMPLE USAGE
-------------

Let's assume the caller is trying to produce a 100,000 satoshi output.

First, the caller estimates the weight of the core (typically 42) and known outputs of the transaction (typically (9 + scriptlen) * 4). For a simple P2WPKH it's a 22 byte scriptpubkey, so that's 124 weight.

It calls "*fundpsbt* 100000sat slow 166", which succeeds, and returns the *psbt* and *feerate\_per\_kw* it used, the *estimated\_final\_weight* and any *excess\_msat*.

If *excess\_msat* is greater than the cost of adding a change output, the caller adds a change output randomly to position 0 or 1 in the PSBT. Say *feerate\_per\_kw* is 253, and the change output is a P2WPKH (weight 124), the cost is around 31 sats. With the dust limit disallowing payments below 546 satoshis, we would only create a change output if *excess\_msat* was greater or equal to 31 + 546.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:fundpsbt#1",
  "method": "fundpsbt",
  "params": {
    "satoshi": 16777216,
    "feerate": "253perkw",
    "startweight": 250,
    "minconf": null,
    "reserve": 0,
    "locktime": null,
    "min_witness_weight": null,
    "excess_as_change": false
  }
}
{
  "id": "example:fundpsbt#2",
  "method": "fundpsbt",
  "params": {
    "satoshi": "all",
    "feerate": "1000perkw",
    "startweight": 1000,
    "minconf": null,
    "reserve": null,
    "locktime": null,
    "min_witness_weight": null,
    "excess_as_change": false
  }
}
{
  "id": "example:fundpsbt#3",
  "method": "fundpsbt",
  "params": {
    "satoshi": "109000sat",
    "feerate": "slow",
    "startweight": 166,
    "minconf": null,
    "reserve": null,
    "locktime": null,
    "min_witness_weight": null,
    "excess_as_change": true
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
  - **was\_reserved** (boolean) (always *false*): Whether this output was previously reserved.
  - **reserved** (boolean) (always *true*): Whether this output is now reserved.
  - **reserved\_to\_block** (u32): The blockheight the reservation will expire.

If *excess\_as\_change* is true and the excess is enough to cover an additional output above the `dust_limit`, then an output is added to the PSBT for the excess amount. The *excess\_msat* will be zero. A *change\_outnum* will be returned with the index of the change output.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "psbt": "cHNidP8BADMCAAAAAWzmSFzhTtXBnQewytc32WaMwJSunScwsYndBNdU80JqAAAAAAD9////AGYAAAAAAQDeAgAAAAABAU1MpIJeOOzqAYVkZaytJCmzUadBVltKar8kWtzKSVeYAAAAAAD9////AoCWmAEAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WXzWm0oAQAAABYAFD8W5uBNZAxN6n1jqU62dxWQbyGAAkcwRAIgUK+vMOeWiDPiJM8fpgKCjjwXog4yfWPvtKES1ZZPaM8CIB3cgouGpV6Gc7nEvAu28Mg9tkAWt/Xl5FDOseEyeZqHASECTwjR0I3gLHdSW7jRmnVXdm0+MgJ1hihnqEfXYeFWA/NlAAAAAQEfgJaYAQAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQA=",
  "feerate_per_kw": 253,
  "estimated_final_weight": 521,
  "excess_msat": 9999869000
}
{
  "psbt": "cHNidP8BAF4CAAAAAfwbEpvpi6D14YV4VLnuVB47Y0uF41kXEyJRL4IusySSAQAAAAD9////ASICAAAAAAAAIlEgeDY1X9yKgtxMsAp3LFVUFR0GOEpN1l6NP2isCFZrhL5nAAAAAAEA9gIAAAAAAQFEkxvLatohY6mw5gr5qG1aiArSrziFPR2YoqD21Hv+RAAAAAAA/f///wJAQg8AAAAAACIAIFuM07kUz2fN2Ppic8kwNT3TZHZzT72WIQLC31O5CIDNrz8PAAAAAAAiUSBj/+5Op9UebK35CG4oaiUnkiqqJbjFOuvzL6MqCmJ/WgJHMEQCIEu1nfVRt9i+rFM219mwhMqdwJsqygWSWTFUS+cemdh6AiBG3Qo8g9J/aAMO2RHDsIBScscj6pTTIwZp7Gw8G3EOKAEhA9dFRFyTYmZfIuDZbp52byc/MmDeo5yKdr+gXdJoTdzPZgAAAAEBK68/DwAAAAAAIlEgY//uTqfVHmyt+QhuKGolJ5IqqiW4xTrr8y+jKgpif1oAAA==",
  "feerate_per_kw": 1000,
  "estimated_final_weight": 1443,
  "excess_msat": 997354000,
  "change_outnum": 0,
  "reservations": [
    {
      "txid": "9224b32e822f5122131759e3854b633b1e54eeb9547885e1f5a08be99b121bfc",
      "vout": 1,
      "was_reserved": false,
      "reserved": true,
      "reserved_to_block": 175
    }
  ]
}
{
  "psbt": "cHNidP8BAF4CAAAAAbEf44mT/BPDxLkUjKy1byWksyLyuM6hbe8shzEbbXhGAQAAAAD9////AU58DQAAAAAAIlEgeDY1X9yKgtxMsAp3LFVUFR0GOEpN1l6NP2isCFZrhL5sAAAAAAEA9gIAAAAAAQEV9Sj1wfHqO/ECZeHp/u7cFL5eRaa1Vu4hXWbwH72pxgEAAAAA/f///wJAQg8AAAAAACIAIFuM07kUz2fN2Ppic8kwNT3TZHZzT72WIQLC31O5CIDNAS8PAAAAAAAiUSBj/+5Op9UebK35CG4oaiUnkiqqJbjFOuvzL6MqCmJ/WgJHMEQCIGILT3DrcNn6/WKOhsxxKq7lDWq47dV0IjRhj0bYHs4yAiApzODtmrz7ifK32G81A2XbBxWboFk2vN4T3ng/hYmb1wEhA9dFRFyTYmZfIuDZbp52byc/MmDeo5yKdr+gXdJoTdzPZgAAAAEBKwEvDwAAAAAAIlEgY//uTqfVHmyt+QhuKGolJ5IqqiW4xTrr8y+jKgpif1oAAA==",
  "feerate_per_kw": 3750,
  "estimated_final_weight": 609,
  "excess_msat": 0,
  "change_outnum": 0,
  "reservations": [
    {
      "txid": "46786d1b31872cef6da1ceb8f222b3a4256fb5ac8c14b9c4c313fc9389e31fb1",
      "vout": 1,
      "was_reserved": false,
      "reserved": true,
      "reserved_to_block": 180
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

lightning-utxopsbt(7), lightning-reserveinputs(7), lightning-unreserveinputs(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
