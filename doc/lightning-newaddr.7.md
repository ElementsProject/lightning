lightning-newaddr -- Command for generating a new address to be used by Core Lightning
======================================================================================

SYNOPSIS
--------

**newaddr** [*addresstype*]

DESCRIPTION
-----------

The **newaddr** RPC command generates a new address which can
subsequently be used to fund channels managed by the Core Lightning node.

The funding transaction needs to be confirmed before funds can be used.

*addresstype* specifies the type of address wanted; currently *bech32*
(e.g. `tb1qu9j4lg5f9rgjyfhvfd905vw46eg39czmktxqgg` on bitcoin testnet
or `bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej` on
bitcoin mainnet), or *p2tr* taproot addresses. The special value *all*
generates all known address types for the same underlying key.

If no *addresstype* is specified the address generated is a *bech32* address.

To send an on-chain payment _from_ the Core Lightning node wallet, use `withdraw`. 

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **p2tr** (string, optional): The taproot address *(added v23.08)*
- **bech32** (string, optional): The bech32 (native segwit) address
- **p2sh-segwit** (string, optional): The p2sh-wrapped address **deprecated, removal in v23.11**

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

If an unrecognized address type is requested an error message will be
returned.

AUTHOR
------

Felix <<fixone@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-listfunds(7), lightning-fundchannel(7), lightning-withdraw(7), lightning-listtransactions(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:f93771e450afe0fc20b2ff9763ba7654d4caf17c35cf45186f2cb9146a67503f)
