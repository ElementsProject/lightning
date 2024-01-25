lightning-multiwithdraw -- Command for withdrawing to multiple addresses
========================================================================

SYNOPSIS
--------

**multiwithdraw** *outputs*  [*feerate*] [*minconf*] [*utxos*]

DESCRIPTION
-----------

The **multiwithdraw** RPC command sends funds from Core Lightning's internal
wallet to the addresses specified in *outputs*,
which is an array containing objects of the form `{address: amount}`.
The `amount` may be the string *"all"*, indicating that all onchain funds
be sent to the specified address.
Otherwise, it is in satoshi precision;
it can be
a whole number,
a whole number ending in *sat*,
a whole number ending in *000msat*,
or a number with 1 to 8 decimal places ending in *btc*.

*feerate* is an optional feerate: see NOTES in lightning-feerates(7)
for possible values.  The default is *normal*.

*minconf* specifies the minimum number of confirmations that used
outputs should have. Default is 1.

*utxos* specifies the utxos to be used to be withdrawn from, as an array
of "txid:vout". These must be drawn from the node's available UTXO set.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **tx** (hex): The raw transaction which was sent
- **txid** (txid): The txid of the **tx**

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, an error is reported and the withdrawal transaction is not
created.

The following error codes may occur:

- -1: Catchall nonspecific error.
- 301: There are not enough funds in the internal wallet (including
fees) to create the transaction.
- 302: The dust limit is not met.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-listfunds(7), lightning-fundchannel(7), lightning-newaddr(7),
lightning-txprepare(7), lightning-withdraw(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:ba123ea4052af7850655f99ee85ed42c0254d7c15ba3861df0574fd58e4d8355)
