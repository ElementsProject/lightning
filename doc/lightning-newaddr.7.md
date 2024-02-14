lightning-newaddr -- Command for generating a new address to be used by Core Lightning
======================================================================================

SYNOPSIS
--------

**newaddr** [*addresstype*] 

DESCRIPTION
-----------

The **newaddr** RPC command generates a new address which can subsequently be used to fund channels managed by the Core Lightning node.

The funding transaction needs to be confirmed before funds can be used.

To send an on-chain payment from the Core Lightning node wallet, use `withdraw`.

- **addresstype** (string, optional) (one of "bech32", "p2tr", "all"): It specifies the type of address wanted; currently *bech32* (e.g. `tb1qu9j4lg5f9rgjyfhvfd905vw46eg39czmktxqgg` on bitcoin testnet or `bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej` on bitcoin mainnet), or *p2tr* taproot addresses. The special value *all* generates all known address types for the same underlying key. The default is *bech32* address.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:newaddr#1",
  "method": "newaddr",
  "params": {
    "addresstype": null
  }
}
{
  "id": "example:newaddr#2",
  "method": "newaddr",
  "params": {
    "addresstype": "bech32"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **p2tr** (string, optional): The taproot address. *(added v23.08)*
- **bech32** (string, optional): The bech32 (native segwit) address.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "bech32": "bcrt1qq8adjz4u6enf0cjey9j8yt0y490tact93fzgsf"
}
{
  "bech32": "bcrt1qq8adjz4u6enf0cjey9j8yt0y490tact93fzgsf"
}
```

ERRORS
------

If an unrecognized address type is requested an error message will be returned.

AUTHOR
------

Felix <<fixone@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-listfunds(7), lightning-fundchannel(7), lightning-withdraw(7), lightning-listtransactions(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
