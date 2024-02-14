lightning-bkpr-listaccountevents -- Command for listing recorded bookkeeping events
===================================================================================

SYNOPSIS
--------

**bkpr-listaccountevents** [*account*] 

DESCRIPTION
-----------

The **bkpr-listaccountevents** RPC command is a list of all bookkeeping events that have been recorded for this node.

If the optional parameter **account** is set, we only emit events for the specified account, if exists.

Note that the type **onchain\_fees** that are emitted are of opposite credit/debit than as they appear in **listincome**, as **listincome** shows all events from the perspective of the node, whereas **listaccountevents** just dumps the event data as we've got it. Onchain fees are updated/recorded as we get more information about input and output spends -- the total onchain fees that were recorded for a transaction for an account can be found by summing all onchain fee events and taking the difference between the **credit\_msat** and **debit\_msat** for these events. We do this so that successive calls to **listaccountevents** always produce the same list of events -- no previously emitted event will be subsequently updated, rather we add a new event to the list.

- **account** (string, optional): Receive events for the specified account.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:bkpr-listaccountevents#1",
  "method": "bkpr-listaccountevents",
  "params": "{}"
}
{
  "id": "example:bkpr-listaccountevents#2",
  "method": "bkpr-listaccountevents",
  "params": [
    "f30a7bab1ec077622d8fe877634bc6dd38bb08122ad49606199c565e0383b2ab"
  ]
}
```

RETURN VALUE
------------

On success, an object containing **events** is returned. It is an array of objects, where each object contains:

- **account** (string): The account name. If the account is a channel, the channel\_id.
- **type** (string) (one of "onchain\_fee", "chain", "channel"): Coin movement type.
- **tag** (string): Description of movement.
- **credit\_msat** (msat): Amount credited.
- **debit\_msat** (msat): Amount debited.
- **currency** (string): Human-readable bech32 part for this coin type.
- **timestamp** (u32): Timestamp this event was recorded by the node. For consolidated events such as onchain\_fees, the most recent timestamp.

If **type** is "chain":
  - **outpoint** (string): The txid:outnum for this event.
  - **blockheight** (u32): For chain events, blockheight this occured at.
  - **origin** (string, optional): The account this movement originated from.
  - **payment\_id** (hex, optional): Lightning payment identifier. For an htlc, this will be the preimage.
  - **txid** (txid, optional): The txid of the transaction that created this event.
  - **description** (string, optional): The description of this event.

If **type** is "onchain\_fee":
  - **txid** (txid): The txid of the transaction that created this event.

If **type** is "channel":
  - **fees\_msat** (msat, optional): Amount paid in fees.
  - **is\_rebalance** (boolean, optional): Is this payment part of a rebalance.
  - **payment\_id** (hex, optional): Lightning payment identifier. For an htlc, this will be the preimage.
  - **part\_id** (u32, optional): Counter for multi-part payments.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "events": [
    {
      "account": "wallet",
      "type": "channel",
      "tag": "journal_entry",
      "credit_msat": 0,
      "debit_msat": 0,
      "currency": "bcrt",
      "timestamp": 1706152911,
      "is_rebalance": false
    },
    {
      "account": "wallet",
      "type": "chain",
      "tag": "deposit",
      "credit_msat": 2000000000,
      "debit_msat": 0,
      "currency": "bcrt",
      "outpoint": "7e202b3b1016e8eb6f4e936215ed6b5bdc63c17e6ebb5e6bce2f98e6757ba44c:0",
      "timestamp": 1706152914,
      "blockheight": 102
    },
    {
      "account": "wallet",
      "type": "chain",
      "tag": "withdrawal",
      "credit_msat": 0,
      "debit_msat": 2000000000,
      "currency": "bcrt",
      "outpoint": "7e202b3b1016e8eb6f4e936215ed6b5bdc63c17e6ebb5e6bce2f98e6757ba44c:0",
      "txid": "6c0a3d8f32f556f3bd8b8c85413c4636a9513c6195abb925ea73c47183d40b7b",
      "timestamp": 1706152921,
      "blockheight": 103
    },
    {
      "account": "wallet",
      "type": "chain",
      "tag": "deposit",
      "credit_msat": 995073000,
      "debit_msat": 0,
      "currency": "bcrt",
      "outpoint": "6c0a3d8f32f556f3bd8b8c85413c4636a9513c6195abb925ea73c47183d40b7b:1",
      "timestamp": 1706152921,
      "blockheight": 103
    },
    {
      "account": "wallet",
      "type": "onchain_fee",
      "tag": "onchain_fee",
      "credit_msat": 1004927000,
      "debit_msat": 0,
      "currency": "bcrt",
      "timestamp": 1706152921,
      "txid": "6c0a3d8f32f556f3bd8b8c85413c4636a9513c6195abb925ea73c47183d40b7b"
    },
    {
      "account": "wallet",
      "type": "onchain_fee",
      "tag": "onchain_fee",
      "credit_msat": 0,
      "debit_msat": 1004927000,
      "currency": "bcrt",
      "timestamp": 1706152921,
      "txid": "6c0a3d8f32f556f3bd8b8c85413c4636a9513c6195abb925ea73c47183d40b7b"
    },
    {
      "account": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "type": "chain",
      "tag": "channel_open",
      "credit_msat": 1000000000,
      "debit_msat": 0,
      "currency": "bcrt",
      "outpoint": "6c0a3d8f32f556f3bd8b8c85413c4636a9513c6195abb925ea73c47183d40b7b:0",
      "timestamp": 1706152922,
      "blockheight": 103
    },
    {
      "account": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "type": "onchain_fee",
      "tag": "onchain_fee",
      "credit_msat": 4927000,
      "debit_msat": 0,
      "currency": "bcrt",
      "timestamp": 1706152922,
      "txid": "6c0a3d8f32f556f3bd8b8c85413c4636a9513c6195abb925ea73c47183d40b7b"
    },
    {
      "account": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "type": "channel",
      "tag": "invoice",
      "credit_msat": 0,
      "debit_msat": 11000000,
      "currency": "bcrt",
      "payment_id": "072b1d20f4a7c757a56d5fb10eaed40b58b68849da41fe396cdbd2d81692875a",
      "part_id": 0,
      "timestamp": 1706152934,
      "description": [
        "XEoCR94SIz6UIRUEkxum."
      ],
      "is_rebalance": false
    },
    {
      "account": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "type": "chain",
      "tag": "channel_close",
      "credit_msat": 0,
      "debit_msat": 989000000,
      "currency": "bcrt",
      "outpoint": "6c0a3d8f32f556f3bd8b8c85413c4636a9513c6195abb925ea73c47183d40b7b:0",
      "txid": "7178638c13a0573f440d9516a23901874b6138338d378b3291cb306c90b3f998",
      "timestamp": 1706152938,
      "blockheight": 104
    },
    {
      "account": "external",
      "origin": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "type": "chain",
      "tag": "to_them",
      "credit_msat": 10899000,
      "debit_msat": 0,
      "currency": "bcrt",
      "outpoint": "7178638c13a0573f440d9516a23901874b6138338d378b3291cb306c90b3f998:0",
      "timestamp": 1706152938,
      "blockheight": 104
    },
    {
      "account": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "type": "onchain_fee",
      "tag": "onchain_fee",
      "credit_msat": 7967000,
      "debit_msat": 0,
      "currency": "bcrt",
      "timestamp": 1706152938,
      "txid": "7178638c13a0573f440d9516a23901874b6138338d378b3291cb306c90b3f998"
    },
    {
      "account": "wallet",
      "type": "chain",
      "tag": "deposit",
      "credit_msat": 980912000,
      "debit_msat": 0,
      "currency": "bcrt",
      "outpoint": "85477738281c1afd652c350025f1d28658fe541c83adc9a7d5276c30cf715a11:0",
      "timestamp": 1706152941,
      "blockheight": 109
    },
    {
      "account": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "type": "chain",
      "tag": "delayed_to_us",
      "credit_msat": 981033000,
      "debit_msat": 0,
      "currency": "bcrt",
      "outpoint": "7178638c13a0573f440d9516a23901874b6138338d378b3291cb306c90b3f998:1",
      "timestamp": 1706152941,
      "blockheight": 104
    },
    {
      "account": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "type": "chain",
      "tag": "to_wallet",
      "credit_msat": 0,
      "debit_msat": 981033000,
      "currency": "bcrt",
      "outpoint": "7178638c13a0573f440d9516a23901874b6138338d378b3291cb306c90b3f998:1",
      "txid": "85477738281c1afd652c350025f1d28658fe541c83adc9a7d5276c30cf715a11",
      "timestamp": 1706152941,
      "blockheight": 109
    },
    {
      "account": "7b0bd48371c473ea25b9ab95613c51a936463c41858c8bbdf356f5328f3d0a6c",
      "type": "onchain_fee",
      "tag": "onchain_fee",
      "credit_msat": 121000,
      "debit_msat": 0,
      "currency": "bcrt",
      "timestamp": 1706152941,
      "txid": "85477738281c1afd652c350025f1d28658fe541c83adc9a7d5276c30cf715a11"
    }
  ]
}
{
  "events": [
    {
      "account": "f30a7bab1ec077622d8fe877634bc6dd38bb08122ad49606199c565e0383b2ab",
      "type": "chain",
      "tag": "channel_proposed",
      "credit_msat": 996363000,
      "debit_msat": 0,
      "currency": "bcrt",
      "outpoint": "abb283035e569c190696d42a1208bb38ddc64b6377e88f2d6277c01eab7b0af3:0",
      "timestamp": 1706246949,
      "blockheight": 0
    },
    {
      "account": "f30a7bab1ec077622d8fe877634bc6dd38bb08122ad49606199c565e0383b2ab",
      "type": "channel",
      "tag": "pushed",
      "credit_msat": 0,
      "debit_msat": 20000000,
      "currency": "bcrt",
      "timestamp": 1706246949,
      "is_rebalance": false
    }
  ]
}
```

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-bkpr-listincome(7), lightning-listfunds(7), lightning-bkpr-listbalances(7), lightning-bkpr-channelsapy(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
