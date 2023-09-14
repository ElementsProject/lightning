lightning-addpsbtoutput -- Command to populate PSBT outputs from the wallet
================================================================

SYNOPSIS
--------

**addpsbtoutput** *satoshi* [*initialpsbt*] [*locktime*]

DESCRIPTION
-----------

`addpsbtoutput` is a low-level RPC command which creates or modifies a PSBT
by adding a single output of amount *satoshi*.

This is used to receive funds into the on-chain wallet interactively
using PSBTs.

*satoshi* is the satoshi value of the output. It can
be a whole number, a whole number ending in *sat*, a whole number
ending in *000msat*, or a number with 1 to 8 decimal places ending in
*btc*.

*initialpsbt* is a PSBT to add the output to. If not speciifed, a PSBT
will be created automatically.

*locktime* is an optional locktime: if not set, it is set to a recent
block height (if no initial psbt is specified).

EXAMPLE USAGE
-------------

Here is a command to make a PSBT with a 100,000 sat output that leads
to the on-chain wallet.
```shell
lightning-cli addpsbtoutput 100000sat
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **psbt** (string): Unsigned PSBT which fulfills the parameters given
- **estimated\_added\_weight** (u32): The estimated weight of the added output
- **outnum** (u32): The 0-based number where the output was placed

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

@dusty\_daemon

SEE ALSO
--------

lightning-fundpsbt(7), lightning-utxopsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:a0c026276fb8402b20336e6f727774fe102a4c5cb6b93ff0ed65a9c6f79d3a83)
