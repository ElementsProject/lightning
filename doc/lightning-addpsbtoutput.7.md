lightning-addpsbtoutput -- Command to populate PSBT outputs from the wallet
================================================================

SYNOPSIS
--------

**addpsbtoutput** *satoshi* [*initialpsbt*] [*locktime*] [*destination*]

DESCRIPTION
-----------

`addpsbtoutput` is a low-level RPC command which creates or modifies a PSBT
by adding a single output of amount *satoshi*.

This is used to receive funds into the on-chain wallet interactively
using PSBTs.

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

Dusty <<@dusty_daemon>> is mainly responsible.

SEE ALSO
--------

lightning-fundpsbt(7), lightning-utxopsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:6a31cc1575f9112d0582b5b9db560a5217d6e1a7bd33d399958e3aff7b022ac3)
