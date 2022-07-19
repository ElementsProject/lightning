lightning-bkpr-inspect -- Command to show onchain footprint of a channel
===================================================================

SYNOPSIS
--------

**bkpr-inspect** *account*

DESCRIPTION
-----------

The **bkpr-inspect** RPC command lists all known on-chain transactions and
associated events for the provided account. Useful for inspecting unilateral
closes for a given channel account. Only valid for channel accounts.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **txs** is returned.  It is an array of objects, where each object contains:
- **txid** (txid): transaction id
- **fees_paid_msat** (msat): Amount paid in sats for this tx
- **outputs** (array of objects):
  - **account** (string): Account this output affected
  - **outnum** (u32): Index of output
  - **output_value_msat** (msat): Value of the output
  - **currency** (string): human-readable bech32 part for this coin type
  - **credit_msat** (msat, optional): Amount credited to account
  - **debit_msat** (msat, optional): Amount debited from account
  - **originating_account** (string, optional): Account this output originated from
  - **output_tag** (string, optional): Description of output creation event
  - **spend_tag** (string, optional): Description of output spend event
  - **spending_txid** (txid, optional): Transaction this output was spent in
  - **payment_id** (hex, optional): lightning payment identifier. For an htlc, this will be the preimage.
- **blockheight** (u32, optional): Blockheight of transaction

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

niftynei <niftynei@gmail.com> is mainly responsible.

SEE ALSO
--------

lightning-listbalances(7), lightning-listfunds(7), lightning-listpeers(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:9df98d40e1ed1b0c72f4a4e8c00d243e10f159b99c534818f04631ec3d17a445)
