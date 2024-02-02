lightning-txprepare -- Command to prepare to withdraw funds from the internal wallet
====================================================================================

SYNOPSIS
--------

**txprepare** *outputs* [*feerate*] [*minconf*] [*utxos*]

DESCRIPTION
-----------

The **txprepare** RPC command creates an unsigned transaction which
spends funds from Core Lightning's internal wallet to the outputs specified
in *outputs*.

**txprepare** is similar to the first part of a **withdraw** command, but
supports multiple outputs and uses *outputs* as parameter. The second part
is provided by **txsend**.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **psbt** (string): the PSBT representing the unsigned transaction
- **unsigned\_tx** (hex): the unsigned transaction
- **txid** (txid): the transaction id of *unsigned\_tx*; you hand this to lightning-txsend(7) or lightning-txdiscard(7), as the inputs of this transaction are reserved.

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

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

[comment]: # ( SHA256STAMP:2711c2b658ca99c61153facb3a532ae3b3a5b8ac86419796e0bf2f7daa6e53c5)
