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
- **fees\_paid\_msat** (msat): Amount paid in sats for this tx
- **outputs** (array of objects):
  - **account** (string): Account this output affected
  - **outnum** (u32): Index of output
  - **output\_value\_msat** (msat): Value of the output
  - **currency** (string): human-readable bech32 part for this coin type
  - **credit\_msat** (msat, optional): Amount credited to account
  - **debit\_msat** (msat, optional): Amount debited from account
  - **originating\_account** (string, optional): Account this output originated from
  - **output\_tag** (string, optional): Description of output creation event
  - **spend\_tag** (string, optional): Description of output spend event
  - **spending\_txid** (txid, optional): Transaction this output was spent in
  - **payment\_id** (hex, optional): lightning payment identifier. For an htlc, this will be the preimage.
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

[comment]: # ( SHA256STAMP:37b3d4030d1301acd105fb750c8a131cc24b00127007fac4e5b83ef19e5e7ade)
