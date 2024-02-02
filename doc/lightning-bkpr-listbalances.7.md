lightning-bkpr-listbalances -- Command for listing current channel + wallet balances
===============================================================================

SYNOPSIS
--------

**bkpr-listbalances**

DESCRIPTION
-----------

The **bkpr-listbalances** RPC command is a list of all current and historical account balances. An account is either the on-chain *wallet* or a channel balance. Any funds sent to an *external* account will not be accounted for here.

Note that any channel that was recorded will be listed. Closed channel balances will be 0msat.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **accounts** is returned.  It is an array of objects, where each object contains:

- **account** (string): The account name. If the account is a channel, the channel\_id
- **balances** (array of objects):
  - **balance\_msat** (msat): Current account balance
  - **coin\_type** (string): coin type, same as HRP for bech32

If **peer\_id** is present:

  - **peer\_id** (pubkey): Node id for the peer this account is with
  - **we\_opened** (boolean): Did we initiate this account open (open the channel)
  - **account\_closed** (boolean): 
  - **account\_resolved** (boolean): Has this channel been closed and all outputs resolved?
  - **resolved\_at\_block** (u32, optional): Blockheight account resolved on chain

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

[comment]: # ( SHA256STAMP:93c258c5a9352584515769c2db1f000ca8b565fea2eeb7a9c262a2edc58ed091)
