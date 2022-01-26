lightning-multiwithdraw -- Command for withdrawing to multiple addresses
========================================================================

SYNOPSIS
--------

**multiwithdraw** *outputs*  [*feerate*] [*minconf*] [*utxos*]

DESCRIPTION
-----------

The **multiwithdraw** RPC command sends funds from c-lightning's internal
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
[comment]: # ( SHA256STAMP:044cdcd69e6ece931b6d0f9b25dd842fd456ee479725e610c03694210256583f)
