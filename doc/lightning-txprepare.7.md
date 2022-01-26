lightning-txprepare -- Command to prepare to withdraw funds from the internal wallet
====================================================================================

SYNOPSIS
--------

**txprepare** *outputs* [*feerate*] [*minconf*] [*utxos*]

DESCRIPTION
-----------

The **txprepare** RPC command creates an unsigned transaction which
spends funds from c-lightning's internal wallet to the outputs specified
in *outputs*.

The *outputs* is the array of output that include *destination*
and *amount*(\{*destination*: *amount*\}). Its format is like:
[\{address1: amount1\}, \{address2: amount2\}]
or
[\{address: *all*\}].
It supports any number of **confirmed** outputs.

The *destination* of output is the address which can be of any Bitcoin accepted
type, including bech32.

The *amount* of output is the amount to be sent from the internal wallet
(expressed, as name suggests, in amount). The string *all* can be used to specify
all available funds. Otherwise, it is in amount precision; it can be a whole
number, a whole number ending in *sat*, a whole number ending in *000msat*,
or a number with 1 to 8 decimal places ending in *btc*.

*feerate* is an optional feerate to use. It can be one of the strings
*urgent* (aim for next block), *normal* (next 4 blocks or so) or *slow*
(next 100 blocks or so) to use lightningd's internal estimates: *normal*
is the default.

Otherwise, *feerate* is a number, with an optional suffix: *perkw* means
the number is interpreted as satoshi-per-kilosipa (weight), and *perkb*
means it is interpreted bitcoind-style as satoshi-per-kilobyte. Omitting
the suffix is equivalent to *perkb*.

*minconf* specifies the minimum number of confirmations that used
outputs should have. Default is 1.

*utxos* specifies the utxos to be used to fund the transaction, as an array
of "txid:vout". These must be drawn from the node's available UTXO set.

**txprepare** is similar to the first part of a **withdraw** command, but
supports multiple outputs and uses *outputs* as parameter. The second part
is provided by **txsend**.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **psbt** (string): the PSBT representing the unsigned transaction
- **unsigned_tx** (hex): the unsigned transaction
- **txid** (txid): the transaction id of *unsigned_tx*; you hand this to lightning-txsend(7) or lightning-txdiscard(7), as the inputs of this transaction are reserved.

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, an error is reported and the transaction is not created.

The following error codes may occur:
- -1: Catchall nonspecific error.
- 301: There are not enough funds in the internal wallet (including
fees) to create the transaction.
- 302: The dust limit is not met.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-withdraw(7), lightning-txsend(7), lightning-txdiscard(7),
lightning-feerates(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:f16a12290870442316c8f3fb552627637610ab6a7cfed9082089040c78dce2be)
