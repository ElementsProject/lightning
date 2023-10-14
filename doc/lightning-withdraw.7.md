lightning-withdraw -- Command for withdrawing funds from the internal wallet
============================================================================

SYNOPSIS
--------

**withdraw** *destination* *satoshi* [*feerate*] [*minconf*] [*utxos*]

DESCRIPTION
-----------

The **withdraw** RPC command sends funds from Core Lightning's internal
wallet to the address specified in *destination*.

The address can be of any Bitcoin accepted type, including bech32.

*satoshi* is the amount to be withdrawn from the internal wallet
(expressed, as name suggests, in satoshi). The string *all* can be used
to specify withdrawal of all available funds (but if we have
any anchor channels, this will always leave at least `min-emergency-msat` as change).
. Otherwise, it is in
satoshi precision; it can be a whole number, a whole number ending in
*sat*, a whole number ending in *000msat*, or a number with 1 to 8
decimal places ending in *btc*.

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

- **tx** (hex): the fully signed bitcoin transaction
- **txid** (txid): the transaction id of *tx*
- **psbt** (string): the PSBT representing the unsigned transaction

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, an error is reported and the withdrawal transaction is not
created.

The following error codes may occur:

- -1: Catchall nonspecific error.
- 301: There are not enough funds in the internal wallet (including
fees) to create the transaction.
- 302: The dust limit is not met.
- 313: The `min-emergency-msat` reserve not be preserved (and we have anchor channels).

AUTHOR
------

Felix <<fixone@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-listfunds(7), lightning-fundchannel(7), lightning-newaddr(7),
lightning-txprepare(7), lightning-feerates(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:38527c3337263c9b4681c976a8148acaaa544f94beb576f2a91b584c3488bfc3)
