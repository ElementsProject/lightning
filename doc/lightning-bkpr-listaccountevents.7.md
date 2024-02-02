lightning-bkpr-listaccountevents -- Command for listing recorded bookkeeping events
=============================================================================

SYNOPSIS
--------

**bkpr-listaccountevents** [\*account\*]

DESCRIPTION
-----------

The **bkpr-listaccountevents** RPC command is a list of all bookkeeping events that have been recorded for this node.

If the optional parameter **account** is set, we only emit events for the
specified account, if exists.

Note that the type **onchain\_fees** that are emitted are of opposite credit/debit than as they appear in **listincome**, as **listincome** shows all events from the perspective of the node, whereas **listaccountevents** just dumps the event data as we've got it. Onchain fees are updated/recorded as we get more information about input and output spends -- the total onchain fees that were recorded for a transaction for an account can be found by summing all onchain fee events and taking the difference between the **credit\_msat** and **debit\_msat** for these events. We do this so that successive calls to **listaccountevents** always
produce the same list of events -- no previously emitted event will be
subsequently updated, rather we add a new event to the list.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **events** is returned.  It is an array of objects, where each object contains:

- **account** (string): The account name. If the account is a channel, the channel\_id
- **type** (string): Coin movement type (one of "onchain\_fee", "chain", "channel")
- **tag** (string): Description of movement
- **credit\_msat** (msat): Amount credited
- **debit\_msat** (msat): Amount debited
- **currency** (string): human-readable bech32 part for this coin type
- **timestamp** (u32): Timestamp this event was recorded by the node. For consolidated events such as onchain\_fees, the most recent timestamp

If **type** is "chain":

  - **outpoint** (string): The txid:outnum for this event
  - **blockheight** (u32): For chain events, blockheight this occured at
  - **origin** (string, optional): The account this movement originated from
  - **payment\_id** (hex, optional): lightning payment identifier. For an htlc, this will be the preimage.
  - **txid** (txid, optional): The txid of the transaction that created this event
  - **description** (string, optional): The description of this event

If **type** is "onchain\_fee":

  - **txid** (txid): The txid of the transaction that created this event

If **type** is "channel":

  - **fees\_msat** (msat, optional): Amount paid in fees
  - **is\_rebalance** (boolean, optional): Is this payment part of a rebalance
  - **payment\_id** (hex, optional): lightning payment identifier. For an htlc, this will be the preimage.
  - **part\_id** (u32, optional): Counter for multi-part payments

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

niftynei <niftynei@gmail.com> is mainly responsible.

SEE ALSO
--------

lightning-bkpr-listincome(7), lightning-listfunds(7),
lightning-bkpr-listbalances(7), lightning-bkpr-channelsapy(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:8d0f6d6d1739fecaeba7ad1f1ae5e36212239dea27d3465a7342ae01dec7ad9c)
