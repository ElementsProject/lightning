lightning-bkpr-inspect -- Command to show onchain footprint of a channel
========================================================================

SYNOPSIS
--------

**bkpr-inspect** *account* 

DESCRIPTION
-----------

The **bkpr-inspect** RPC command lists all known on-chain transactions and associated events for the provided account. Useful for inspecting unilateral closes for a given channel account. Only valid for channel accounts.

- **account** (string): Channel account to inspect.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:bkpr-inspect#1",
  "method": "bkpr-inspect",
  "params": [
    "f30a7bab1ec077622d8fe877634bc6dd38bb08122ad49606199c565e0383b2ab"
  ]
}
```

RETURN VALUE
------------

On success, an object containing **txs** is returned. It is an array of objects, where each object contains:

- **txid** (txid): Transaction id.
- **fees\_paid\_msat** (msat): Amount paid in sats for this tx.
- **outputs** (array of objects):
  - **account** (string): Account this output affected.
  - **outnum** (u32): Index of output.
  - **output\_value\_msat** (msat): Value of the output.
  - **currency** (string): Human-readable bech32 part for this coin type.
  - **credit\_msat** (msat, optional): Amount credited to account.
  - **debit\_msat** (msat, optional): Amount debited from account.
  - **originating\_account** (string, optional): Account this output originated from.
  - **output\_tag** (string, optional): Description of output creation event.
  - **spend\_tag** (string, optional): Description of output spend event.
  - **spending\_txid** (txid, optional): Transaction this output was spent in.
  - **payment\_id** (hex, optional): Lightning payment identifier. For an htlc, this will be the preimage.
- **blockheight** (u32, optional): Blockheight of transaction.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "txs": [
    {
      "txid": "abb283035e569c190696d42a1208bb38ddc64b6377e88f2d6277c01eab7b0af3",
      "fees_paid_msat": 0,
      "outputs": [
        {
          "account": "f30a7bab1ec077622d8fe877634bc6dd38bb08122ad49606199c565e0383b2ab",
          "outnum": 0,
          "output_tag": "channel_proposed",
          "output_value_msat": 996363000,
          "credit_msat": 996363000,
          "currency": "bcrt"
        }
      ]
    }
  ]
}
```

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-listbalances(7), lightning-listfunds(7), lightning-listpeers(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
