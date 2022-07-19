lightning-bkpr-listincome -- Command for listing all income impacting events
=======================================================================

SYNOPSIS
--------

**bkpr-listincome** \[*consolidate_fees*\] \[*start_time*\] \[*end_time*\]

DESCRIPTION
-----------

The **bkpr-listincome** RPC command is a list of all income impacting events that the bookkeeper plugin has recorded for this node.

If **consolidate_fees** is true, we emit a single, consolidated event for
any onchain-fees for a txid and account. Otherwise, events for every update to
the onchain fee calculation for this account and txid will be printed. Defaults to true. Note that this means that the events emitted are non-stable,
i.e. calling **listincome** twice may result in different onchain fee events
being emitted, depending on how much information we've logged for that
transaction.

The **start_time** is a UNIX timestamp (in seconds) that filters events after the provided timestamp. Defaults to zero.

The **end_time** is a UNIX timestamp (in seconds) that filters events up to and at the provided timestamp. Defaults to max-int.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **income_events** is returned.  It is an array of objects, where each object contains:
- **account** (string): The account name. If the account is a channel, the channel_id
- **tag** (string): Type of income event
- **credit_msat** (msat): Amount earned (income)
- **debit_msat** (msat): Amount spent (expenses)
- **currency** (string): human-readable bech32 part for this coin type
- **timestamp** (u32): Timestamp this event was recorded by the node. For consolidated events such as onchain_fees, the most recent timestamp
- **description** (string, optional): More information about this event. If a `invoice` type, typically the bolt11/bolt12 description
- **outpoint** (string, optional): The txid:outnum for this event, if applicable
- **txid** (txid, optional): The txid of the transaction that created this event, if applicable
- **payment_id** (hex, optional): lightning payment identifier. For an htlc, this will be the preimage.

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

niftynei <niftynei@gmail.com> is mainly responsible.

SEE ALSO
--------

lightning-bkpr-listaccountevents(7), lightning-listfunds(7),
lightning-bkpr-listbalances(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:ab8508af0f40587c5a804f6981591564fe2d18b4fe3fbe7793e6a489607f7e0a)
