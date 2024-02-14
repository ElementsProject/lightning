lightning-addpsbtoutput -- Command to populate PSBT outputs from the wallet
===========================================================================

SYNOPSIS
--------

**addpsbtoutput** *satoshi* [*initialpsbt*] [*locktime*] [*destination*] 

DESCRIPTION
-----------

Command *added* in v23.11.

`addpsbtoutput` is a low-level RPC command which creates or modifies a PSBT by adding a single output of amount *satoshi*.

This is used to receive funds into the on-chain wallet interactively using PSBTs.

- **satoshi** (sat): The satoshi value of the output. It can be a whole number, a whole number ending in *sat*, or a number with 1 to 8 decimal places ending in *btc*.
- **initialpsbt** (string, optional): Base 64 encoded PSBT to add the output to. If not specified, one will be generated automatically.
- **locktime** (u32, optional): If not set, it is set to a recent block height (if no initial psbt is specified).
- **destination** (string, optional): If it is not set, an internal address is generated.

EXAMPLE USAGE
-------------

Here is a command to make a PSBT with a 100,000 sat output that leads to the on-chain wallet.

```shell
lightning-cli addpsbtoutput 100000sat
```

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:addpsbtoutput#1",
  "method": "addpsbtoutput",
  "params": {
    "satoshi": 100000,
    "initialpsbt": null,
    "locktime": null,
    "destination": null
  }
}
{
  "id": "example:addpsbtoutput#2",
  "method": "addpsbtoutput",
  "params": {
    "satoshi": 1000000,
    "initialpsbt": null,
    "locktime": 111,
    "destination": null
  }
}
{
  "id": "example:addpsbtoutput#3",
  "method": "addpsbtoutput",
  "params": {
    "satoshi": 974343,
    "initialpsbt": "cHNidP8BAF4CAAAAAfwbEpvpi6D14YV4VLnuVB47Y0uF41kXEyJRL4IusySSAQAAAAD9////ASICAAAAAAAAIlEgeDY1X9yKgtxMsAp3LFVUFR0GOEpN1l6NP2isCFZrhL5nAAAAAAEA9gIAAAAAAQFEkxvLatohY6mw5gr5qG1aiArSrziFPR2YoqD21Hv+RAAAAAAA/f///wJAQg8AAAAAACIAIFuM07kUz2fN2Ppic8kwNT3TZHZzT72WIQLC31O5CIDNrz8PAAAAAAAiUSBj/+5Op9UebK35CG4oaiUnkiqqJbjFOuvzL6MqCmJ/WgJHMEQCIEu1nfVRt9i+rFM219mwhMqdwJsqygWSWTFUS+cemdh6AiBG3Qo8g9J/aAMO2RHDsIBScscj6pTTIwZp7Gw8G3EOKAEhA9dFRFyTYmZfIuDZbp52byc/MmDeo5yKdr+gXdJoTdzPZgAAAAEBK68/DwAAAAAAIlEgY//uTqfVHmyt+QhuKGolJ5IqqiW4xTrr8y+jKgpif1oAAA==",
    "locktime": null,
    "destination": "bcrt1q9tc6q49l6wrrtp8ul45rj92hsleehwwxty32zu"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **psbt** (string): Unsigned PSBT which fulfills the parameters given.
- **estimated\_added\_weight** (u32): The estimated weight of the added output.
- **outnum** (u32): The 0-based number where the output was placed.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "psbt": "cHNidP8BAgQCAAAAAQMEbAAAAAEEAQABBQEBAQYBAwH7BAIAAAAAAQMIoIYBAAAAAAABBCJRIHg2NV/cioLcTLAKdyxVVBUdBjhKTdZejT9orAhWa4S+AA==",
  "estimated_added_weight": 172,
  "outnum": 0
}
{
  "psbt": "cHNidP8BAgQCAAAAAQMEbwAAAAEEAQABBQEBAQYBAwH7BAIAAAAAAQMIQEIPAAAAAAABBCJRIJd6ICNAQALFOMhoUHuSVSuzcaUdkDKlk4K+A+DR9+4uAA==",
  "estimated_added_weight": 172,
  "outnum": 0
}
{
  "psbt": "cHNidP8BAH0CAAAAAfwbEpvpi6D14YV4VLnuVB47Y0uF41kXEyJRL4IusySSAQAAAAD9////AiICAAAAAAAAIlEgeDY1X9yKgtxMsAp3LFVUFR0GOEpN1l6NP2isCFZrhL4H3g4AAAAAABYAFCrxoFS/04Y1hPz9aDkVV4fzm7nGZwAAAAABAPYCAAAAAAEBRJMby2raIWOpsOYK+ahtWogK0q84hT0dmKKg9tR7/kQAAAAAAP3///8CQEIPAAAAAAAiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAza8/DwAAAAAAIlEgY//uTqfVHmyt+QhuKGolJ5IqqiW4xTrr8y+jKgpif1oCRzBEAiBLtZ31UbfYvqxTNtfZsITKncCbKsoFklkxVEvnHpnYegIgRt0KPIPSf2gDDtkRw7CAUnLHI+qU0yMGaexsPBtxDigBIQPXRURck2JmXyLg2W6edm8nPzJg3qOcina/oF3SaE3cz2YAAAABASuvPw8AAAAAACJRIGP/7k6n1R5srfkIbihqJSeSKqoluMU66/MvoyoKYn9aAAAA",
  "estimated_added_weight": 172,
  "outnum": 1
}
```

AUTHOR
------

Dusty <<@dusty\_daemon>> is mainly responsible.

SEE ALSO
--------

lightning-fundpsbt(7), lightning-utxopsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
