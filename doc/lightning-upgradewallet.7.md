lightning-upgradewallet -- Command to spend all P2SH-wrapped inputs into a Native Segwit output
================================================================

SYNOPSIS
--------

**upgradewallet** [*feerate*] [*reservedok*]

DESCRIPTION
-----------

`upgradewallet` is a convenience RPC which will spend all p2sh-wrapped
Segwit deposits in a wallet into a single Native Segwit P2WPKH address.

*feerate* can be one of the feerates listed in lightning-feerates(7),
or one of the strings *urgent* (aim for next block), *normal* (next 4
blocks or so) or *slow* (next 100 blocks or so) to use lightningd's
internal estimates.  It can also be a *feerate* is a number, with an
optional suffix: *perkw* means the number is interpreted as
satoshi-per-kilosipa (weight), and *perkb* means it is interpreted
bitcoind-style as satoshi-per-kilobyte. Omitting the suffix is
equivalent to *perkb*.

*reservedok* tells the wallet to include all P2SH-wrapped inputs, including
reserved ones.

EXAMPLE USAGE
-------------

The caller is trying to buy a liquidity ad but the command keeps failing.
They have funds in their wallet, but they're all P2SH-wrapped outputs.

The caller can call `upgradewallet` to convert their funds to native segwit
outputs, which are valid for liquidity ad buys.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
[comment]: # (GENERATE-FROM-SCHEMA-END)


AUTHOR
------

~niftynei~ <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-utxopsbt(7), lightning-reserveinputs(7), lightning-unreserveinputs(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:0f290582f49c6103258b7f781a9e7fa4075ec6c05335a459a91da0b6fd58c68d)
