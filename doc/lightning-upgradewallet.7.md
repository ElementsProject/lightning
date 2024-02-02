lightning-upgradewallet -- Command to spend all P2SH-wrapped inputs into a Native Segwit output
================================================================

SYNOPSIS
--------

**upgradewallet** [*feerate*] [*reservedok*]

DESCRIPTION
-----------

`upgradewallet` is a convenience RPC which will spend all p2sh-wrapped
Segwit deposits in a wallet into a single Native Segwit P2WPKH address.

*feerate* is an optional feerate: see NOTES in lightning-feerates(7)
for possible values. The default is *opening*.

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
