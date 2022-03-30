lightning-bkpr-listbalances -- Command for listing current channel + wallet balances
===============================================================================

SYNOPSIS
--------

**bkpr-listbalances**

DESCRIPTION
-----------

The **bkpr-listbalances** RPC command is a list of all current and historical account balances. An account is either the on-chain *wallet* or a channel balance.
Any funds sent to an *external* account will not be accounted for here.

Note that any channel that was recorded will be listed. Closed channel balances
will be 0msat.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **accounts** is returned.  It is an array of objects, where each object contains:
- **account** (string): The account name. If the account is a channel, the channel_id
- **balances** (array of objects):
  - **balance_msat** (msat): Current account balance
  - **coin_type** (string): coin type, same as HRP for bech32

If **peer_id** is present:
  - **peer_id** (pubkey): Node id for the peer this account is with
  - **we_opened** (boolean): Did we initiate this account open (open the channel)
  - **account_closed** (boolean): 
  - **account_resolved** (boolean): Has this channel been closed and all outputs resolved?
  - **resolved_at_block** (u32, optional): Blockheight account resolved on chain

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

niftynei <niftynei@gmail.com> is mainly responsible.

SEE ALSO
--------

lightning-bkpr-listincome(7), lightning-listfunds(7),
lightning-bkpr-listaccountevents(7),
lightning-bkpr-channelsapy(7), lightning-listpeers(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:8c621971c5b42473f0299f10fad914a8d504f5f608c1a136b8726e0d5d33494b)
