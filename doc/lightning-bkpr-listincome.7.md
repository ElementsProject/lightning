lightning-bkpr-listincome -- Command for listing all income impacting events
============================================================================

SYNOPSIS
--------

**bkpr-listincome** [*consolidate\_fees*] [*start\_time*] [*end\_time*] 

DESCRIPTION
-----------

Command *added* in pre-v0.10.1.

The **bkpr-listincome** RPC command is a list of all income impacting events that the bookkeeper plugin has recorded for this node.

- **consolidate\_fees** (boolean, optional): If true, we emit a single, consolidated event for any onchain-fees for a txid and account. Otherwise, events for every update to the onchain fee calculation for this account and txid will be printed. Note that this means that the events emitted are non-stable, i.e. calling **listincome** twice may result in different onchain fee events being emitted, depending on how much information we've logged for that transaction. The default is True.
- **start\_time** (u32, optional): UNIX timestamp (in seconds) that filters events after the provided timestamp. The default is zero.
- **end\_time** (u32, optional): UNIX timestamp (in seconds) that filters events up to and at the provided timestamp. The default is max-int.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:bkpr-listincome#1",
  "method": "bkpr-listincome",
  "params": "{}"
}
{
  "id": "example:bkpr-listincome#2",
  "method": "bkpr-listincome",
  "params": {
    "consolidate_fees": false
  }
}
```

RETURN VALUE
------------

On success, an object containing **income\_events** is returned. It is an array of objects, where each object contains:

- **account** (string): The account name. If the account is a channel, the channel\_id.
- **tag** (string): Type of income event.
- **credit\_msat** (msat): Amount earned (income).
- **debit\_msat** (msat): Amount spent (expenses).
- **currency** (string): Human-readable bech32 part for this coin type.
- **timestamp** (u32): Timestamp this event was recorded by the node. For consolidated events such as onchain\_fees, the most recent timestamp.
- **description** (string, optional): More information about this event. If a `invoice` type, typically the bolt11/bolt12 description.
- **outpoint** (string, optional): The txid:outnum for this event, if applicable.
- **txid** (txid, optional): The txid of the transaction that created this event, if applicable.
- **payment\_id** (hex, optional): Lightning payment identifier. For an htlc, this will be the preimage.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "income_events": [
    {
      "account": "wallet",
      "tag": "deposit",
      "credit_msat": 1111111000,
      "debit_msat": 0,
      "currency": "bcrt",
      "timestamp": 1706153060,
      "outpoint": "6d813d2e99ae7181b61e59ff224c43de698bd08b8ca5b8034ccc13aa7b6428ef:0"
    },
    {
      "account": "wallet",
      "tag": "deposit",
      "credit_msat": 1111111000,
      "debit_msat": 0,
      "currency": "bcrt",
      "timestamp": 1706153060,
      "outpoint": "0bbbe965f76525af3876ae6f1520d91047d4be04cb4e46b7229120a60c5dc9c5:0"
    }
  ]
}
{
  "income_events": [
    {
      "account": "wallet",
      "tag": "deposit",
      "credit_msat": 1111111000,
      "debit_msat": 0,
      "currency": "bcrt",
      "timestamp": 1708624181,
      "outpoint": "895b5eaad4544d24c99628883b4d84b2c6024d6a2da4c1de54098d985f280943:1"
    },
    {
      "account": "wallet",
      "tag": "withdrawal",
      "credit_msat": 0,
      "debit_msat": 555555000,
      "currency": "bcrt",
      "timestamp": 1708624182,
      "outpoint": "d28a2cba55da10700ddd7f1f23618160dafb3134650055654551d9b0382dcd71:0"
    },
    {
      "account": "wallet",
      "tag": "onchain_fee",
      "credit_msat": 0,
      "debit_msat": 555556000,
      "currency": "bcrt",
      "timestamp": 1708624183,
      "txid": "d28a2cba55da10700ddd7f1f23618160dafb3134650055654551d9b0382dcd71"
    },
    {
      "account": "wallet",
      "tag": "onchain_fee",
      "credit_msat": 554947000,
      "debit_msat": 0,
      "currency": "bcrt",
      "timestamp": 1708624183,
      "txid": "d28a2cba55da10700ddd7f1f23618160dafb3134650055654551d9b0382dcd71"
    }
  ]
}
```

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-bkpr-listaccountevents(7), lightning-listfunds(7), lightning-bkpr-listbalances(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
