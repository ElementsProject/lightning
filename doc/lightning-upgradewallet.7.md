lightning-upgradewallet -- Command to spend all P2SH-wrapped inputs into a Native Segwit output
===============================================================================================

SYNOPSIS
--------

**upgradewallet** [*feerate*] [*reservedok*] 

DESCRIPTION
-----------

`upgradewallet` is a convenience RPC which will spend all p2sh-wrapped Segwit deposits in a wallet into a single Native Segwit P2WPKH address.

- **feerate** (feerate, optional): Feerate for the upgrade transaction. The default is *opening*. *(added v23.02)*
- **reservedok** (boolean, optional): Tells the wallet to include all P2SH-wrapped inputs, including reserved ones. *(added v23.02)*

EXAMPLE USAGE
-------------

The caller is trying to buy a liquidity ad but the command keeps failing. They have funds in their wallet, but they're all P2SH-wrapped outputs.

The caller can call `upgradewallet` to convert their funds to native segwit outputs, which are valid for liquidity ad buys.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:upgradewallet#1",
  "method": "upgradewallet",
  "params": "{}"
}
{
  "id": "example:upgradewallet#2",
  "method": "upgradewallet",
  "params": {
    "feerate": "urgent",
    "reservedok": true
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **upgraded\_outs** (u64): Count of spent/upgraded UTXOs. *(added v23.02)*
- **psbt** (string, optional): The PSBT that was finalized and sent. *(added v23.02)*
- **tx** (hex, optional): The raw transaction which was sent. *(added v23.02)*
- **txid** (txid, optional): The txid of the **tx**. *(added v23.02)*

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "upgraded_outs": 0
}
{
  "tx": "0200000001c08ce0a9ea1e00179ea603cb8619ec2a2df990ef931e1ccd87fa7a0e271ed8370100000000fdffffff013514310100000000225120888ab14b6e1655d1d00039b836d70b66e3351543ab6cd2f94166255f3d5e6cb5cf000000",
  "txid": "de5f1d6f0b2f95cfe5cfbf8cc33bd3f279a8f800ee0efc27bbfafb2b6ead9560",
  "psbt": "cHNidP8BAgQCAAAAAQMEzwAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQDgAgAAAAABAZRZ0m0kaJA+ubJw1eYurGROu1BYc0i7l9xbyG06R6uZAQAAAAD9////AmQtPCgBAAAAF6kUnoGu9IUv0FGnzol3Lb/BNBNkOViHAC0xAQAAAAAXqRRlVyjzbP420BqlDTI2cERp+EpVQIcCRzBEAiBliJpjBsipwFgsLZMlzbESZ6hMTh+pgKQlXUIL0nLb3wIga/xwr/IJgEc7Ie6ApS4aVDr9xr1TZ3wj+8bRvI6WqScBIQPgYuc48PzUufScX6A6YOsdmJwn+bAQjLZ/g9jhQYduHM4AAAABASAALTEBAAAAABepFGVXKPNs/jbQGqUNMjZwRGn4SlVAhyICArnAxoROEqUxyWjlXFUHjsFtm/dr6SkP2H0cynK0g5oXRzBEAiBlTUNYfS5n5rGRVmoNb0z3AMGJjHijwpXROGIVxfoBnQIgeTx32KY3CcfYTYzXUIRQAMUQB7rlPWRptWMDD3UttkcBAQQWABTWuWnTbf/a2YaRk/Zj7kgN/cc0iCIGArnAxoROEqUxyWjlXFUHjsFtm/dr6SkP2H0cynK0g5oXCNa5adMAAAAAAQ4gwIzgqeoeABeepgPLhhnsKi35kO+THhzNh/p6Dice2DcBDwQBAAAAARAE/f///wABAwg1FDEBAAAAAAEEIlEgiIqxS24WVdHQADm4NtcLZuM1FUOrbNL5QWYlXz1ebLUhByjMj8l44gnxaV+ltWVQYdsaqyMRtSQXaUW/EBXvLUuJCQCftnv8BwAAAAA=",
  "upgraded_outs": 1
}
```

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-utxopsbt(7), lightning-reserveinputs(7), lightning-unreserveinputs(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
