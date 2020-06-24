lightning-reserveinputs -- Construct a transaction and reserve the UTXOs it spends
==================================================================================

SYNOPSIS
--------

**reserveinputs** *outputs* \[*feerate*\] \[*minconf*\] \[*utxos*\] \[*expire_after*\]

DESCRIPTION
-----------

The **reserveinputs** RPC command creates an unsigned PSBT which
spends funds from c-lightning’s internal wallet to the outputs specified
in *outputs*.

The *outputs* is the array of output that include *destination*
and *amount*(\{*destination*: *amount*\}). Its format is like:
\[\{address1: amount1\}, \{address2: amount2\}\]
or
\[\{address: *all*\}\].
It supports any number of outputs.

The *destination* of output is the address which can be of any Bitcoin accepted
type, including bech32.

The *amount* of output is the amount to be sent from the internal wallet
(expressed, as name suggests, in amount). The string *all* can be used to specify
all available funds. Otherwise, it is in amount precision; it can be a whole
number, a whole number ending in *sat*, a whole number ending in *000msat*,
or a number with 1 to 8 decimal places ending in *btc*.

*feerate* is an optional feerate to use. It can be one of the strings
*urgent* (aim for next block), *normal* (next 4 blocks or so) or *slow*
(next 100 blocks or so) to use lightningd’s internal estimates: *normal*
is the default.

Otherwise, *feerate* is a number, with an optional suffix: *perkw* means
the number is interpreted as satoshi-per-kilosipa (weight), and *perkb*
means it is interpreted bitcoind-style as satoshi-per-kilobyte. Omitting
the suffix is equivalent to *perkb*.

*minconf* specifies the minimum number of confirmations that reserved UTXOs 
should have. Default is 1.

*utxos* specifies the utxos to be used to fund the transaction, as an array
of "txid:vout". These must be drawn from the node's available UTXO set.

*expire_after* specifies the number of blocks after which the UTXOs reserved
by this command will be eligible for re-use. Defaults to 144 blocks.
Can be disabled by passing in 0.


RETURN VALUE
------------

On success, an object with attributes *psbt* and *feerate_per_kw* will be
returned. The inputs of the *psbt* have been marked as reserved in the internal wallet.

On failure, an error is reported and no UTXOs are reserved.

The following error codes may occur:
- -1: Catchall nonspecific error.
- 301: There are not enough funds in the internal wallet (including
fees) to create the transaction.
- 302: The dust limit is not met.

AUTHOR
------

niftynei <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-unreserveinputs(7), lightning-signpsbt(7), lightning-sendpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
