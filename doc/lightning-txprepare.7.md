LIGHTNING-TXPREPARE(7) Manual Page
==================================
lightning-txprepare - Command to prepare to withdraw funds from the
internal wallet.

SYNOPSIS
--------

**txprepare** *destination* *satoshi* \[*feerate*\] \[*minconf*\]

DESCRIPTION
-----------

The **txprepare** RPC command creates an unsigned transaction which
spends funds from c-lightning’s internal wallet to the address specified
in *destination*.

Effectively, it is the first part of a **withdraw** command, and uses
the same parameters. The second part is provided by **txsend**.

RETURN VALUE
------------

On success, an object with attributes *unsigned\_tx* and *txid* will be
returned. You need to hand *txid* to **txsend** or **txdiscard**, as the
inputs of this transaction are reserved until then, or until the daemon
restarts.

*unsigned\_tx* represents the raw bitcoin transaction (not yet signed)
and *txid* represent the bitcoin transaction id.

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

lightning-withdraw(7), lightning-txsend(7), lightning-txdiscard(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

------------------------------------------------------------------------

Last updated 2019-06-08 16:03:59 CEST
