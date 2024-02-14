lightning-listfunds -- Command showing all funds currently managed by the Core Lightning node
=============================================================================================

SYNOPSIS
--------

**listfunds** [*spent*] 

DESCRIPTION
-----------

The **listfunds** RPC command displays all funds available, either in unspent outputs (UTXOs) in the internal wallet or funds locked in currently open channels.

- **spent** (boolean, optional): If True, then the *outputs* will include spent outputs in addition to the unspent ones. The default is False.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listfunds#1",
  "method": "listfunds",
  "params": {
    "spent": null
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **outputs** (array of objects):
  - **txid** (txid): The ID of the spendable transaction.
  - **output** (u32): The index within *txid*.
  - **amount\_msat** (msat): The amount of the output.
  - **scriptpubkey** (hex): The scriptPubkey of the output.
  - **status** (string) (one of "unconfirmed", "confirmed", "spent", "immature")
  - **reserved** (boolean): Whether this UTXO is currently reserved for an in-flight tx.
  - **address** (string, optional): The bitcoin address of the output.
  - **redeemscript** (hex, optional): The redeemscript, only if it's p2sh-wrapped.

  If **status** is "confirmed":
    - **blockheight** (u32): Block height where it was confirmed.

  If **reserved** is "true":
    - **reserved\_to\_block** (u32): Block height where reservation will expire.
- **channels** (array of objects):
  - **peer\_id** (pubkey): The peer with which the channel is opened.
  - **our\_amount\_msat** (msat): Available satoshis on our node's end of the channel.
  - **amount\_msat** (msat): Total channel value.
  - **funding\_txid** (txid): Funding transaction id.
  - **funding\_output** (u32): The 0-based index of the output in the funding transaction.
  - **connected** (boolean): Whether the channel peer is connected.
  - **state** (string) (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN", "DUALOPEND\_OPEN\_COMMITTED", "DUALOPEND\_OPEN\_COMMIT\_READY"): The channel state, in particular `CHANNELD_NORMAL` means the channel can be used normally.
  - **channel\_id** (hash): The full channel\_id (funding txid Xored with output number). *(added v23.05)*

  If **state** is "CHANNELD\_NORMAL":
    - **short\_channel\_id** (short\_channel\_id): Short channel id of channel.

  If **state** is "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN" or "ONCHAIN":
    - **short\_channel\_id** (short\_channel\_id, optional): Short channel id of channel (only if funding reached lockin depth before closing).

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "outputs": [
    {
      "txid": "0f184b101569bf777af3449fa266948a9d55768f97867e48416a2c92858dd1bc",
      "output": 1,
      "amount_msat": 1111111000,
      "scriptpubkey": "001401fad90abcd66697e2592164722de4a95ebee165",
      "address": "bcrt1qq8adjz4u6enf0cjey9j8yt0y490tact93fzgsf",
      "status": "confirmed",
      "blockheight": 102,
      "reserved": false
    },
    {
      "txid": "4bee7dc3a28f2434e9bb3e9aaab418dd276485a8705b0f787bf741d3f979ec3b",
      "output": 1,
      "amount_msat": 1111111000,
      "scriptpubkey": "001401fad90abcd66697e2592164722de4a95ebee165",
      "address": "bcrt1qq8adjz4u6enf0cjey9j8yt0y490tact93fzgsf",
      "status": "confirmed",
      "blockheight": 102,
      "reserved": false
    }
  ],
  "channels": []
}
```

AUTHOR
------

Felix <<fixone@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-newaddr(7), lightning-fundchannel(7), lightning-withdraw(7), lightning-listtransactions(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
