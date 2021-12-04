lightning-listtransactions -- Command to get the list of transactions that was stored in the wallet.
============================================================

SYNOPSIS
--------

**listtransactions**

DESCRIPTION
-----------

The **listtransactions** command returns transactions tracked in the wallet. This includes deposits, withdrawals and transactions related to channels. A transaction may have multiple types, e.g., a transaction may both be a close and a deposit if it closes the channel and returns funds to the wallet.

EXAMPLE JSON REQUEST
------------
```json
{
  "id": 82,
  "method": "listtransactions",
  "params": {}
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **transactions** is returned.  It is an array of objects, where each object contains:
- **hash** (txid): the transaction id
- **rawtx** (hex): the raw transaction
- **blockheight** (u32): the block height of this tx
- **txindex** (u32): the transaction number within the block
- **locktime** (u32): The nLocktime for this tx
- **version** (u32): The nVersion for this tx
- **inputs** (array of objects): Each input, in order:
  - **txid** (txid): the transaction id spent
  - **index** (u32): the output spent
  - **sequence** (u32): the nSequence value
  - **type** (string, optional): the purpose of this input (*EXPERIMENTAL_FEATURES* only) (one of "theirs", "deposit", "withdraw", "channel_funding", "channel_mutual_close", "channel_unilateral_close", "channel_sweep", "channel_htlc_success", "channel_htlc_timeout", "channel_penalty", "channel_unilateral_cheat")
  - **channel** (short_channel_id, optional): the channel this input is associated with (*EXPERIMENTAL_FEATURES* only)
- **outputs** (array of objects): Each output, in order:
  - **index** (u32): the 0-based output number
  - **msat** (msat): the amount of the output
  - **scriptPubKey** (hex): the scriptPubKey
  - **type** (string, optional): the purpose of this output (*EXPERIMENTAL_FEATURES* only) (one of "theirs", "deposit", "withdraw", "channel_funding", "channel_mutual_close", "channel_unilateral_close", "channel_sweep", "channel_htlc_success", "channel_htlc_timeout", "channel_penalty", "channel_unilateral_cheat")
  - **channel** (short_channel_id, optional): the channel this output is associated with (*EXPERIMENTAL_FEATURES* only)
- **type** (array of strings, optional):
  - Reason we care about this transaction (*EXPERIMENTAL_FEATURES* only) (one of "theirs", "deposit", "withdraw", "channel_funding", "channel_mutual_close", "channel_unilateral_close", "channel_sweep", "channel_htlc_success", "channel_htlc_timeout", "channel_penalty", "channel_unilateral_cheat")
- **channel** (short_channel_id, optional): the channel this transaction is associated with (*EXPERIMENTAL_FEATURES* only)

[comment]: # (GENERATE-FROM-SCHEMA-END)
  
On failure, one of the following error codes may be returned:
- -32602: Error in given parameters.

EXAMPLE JSON RESPONSE
-----
```json
{
   "transactions": [
      {
         "hash": "05985072bbe20747325e69a159fe08176cc1bbc96d25e8848edad2dddc1165d0",
         "rawtx": "02000000027032912651fc25a3e0893acd5f9640598707e2dfef92143bb5a4020e335442800100000017160014a5f48b9aa3cb8ca6cc1040c11e386745bb4dc932ffffffffd229a4b4f78638ebcac10a68b0561585a5d6e4d3b769ad0a909e9b9afaeae24e00000000171600145c83da9b685f9142016c6f5eb5f98a45cfa6f686ffffffff01915a01000000000017a9143a4dfd59e781f9c3018e7d0a9b7a26d58f8d22bf8700000000",
         "blockheight": 0,
         "txindex": 0,
         "locktime": 0,
         "version": 2,
         "inputs": [
            {
               "txid": "804254330e02a4b53b1492efdfe207875940965fcd3a89e0a325fc5126913270",
               "index": 1,
               "sequence": 4294967295
            },
            {
               "txid": "4ee2eafa9a9b9e900aad69b7d3e4d6a5851556b0680ac1caeb3886f7b4a429d2",
               "index": 0,
               "sequence": 4294967295
            }
         ],
         "outputs": [
            {
               "index": 0,
               "satoshis": "88721000msat",
               "scriptPubKey": "a9143a4dfd59e781f9c3018e7d0a9b7a26d58f8d22bf87"
            }
         ]
      }
    ]
}
```


AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

lightning-newaddr(7), lightning-listfunds(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:ba0624377601e6e90c2ca90b709fd076f3ed0f2b813f73553ec6b935eeec54a1)
