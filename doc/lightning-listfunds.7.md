lightning-listfunds -- Command showing all funds currently managed by the Core Lightning node
==========================================================================================

SYNOPSIS
--------

**listfunds** [*spent*]

DESCRIPTION
-----------

The **listfunds** RPC command displays all funds available, either in
unspent outputs (UTXOs) in the internal wallet or funds locked in
currently open channels.

*spent* is a boolean: if true, then the *outputs* will include spent outputs
in addition to the unspent ones. Default is false.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **outputs** (array of objects):
  - **txid** (txid): the ID of the spendable transaction
  - **output** (u32): the index within *txid*
  - **amount\_msat** (msat): the amount of the output
  - **scriptpubkey** (hex): the scriptPubkey of the output
  - **status** (string) (one of "unconfirmed", "confirmed", "spent", "immature")
  - **reserved** (boolean): whether this UTXO is currently reserved for an in-flight tx
  - **address** (string, optional): the bitcoin address of the output
  - **redeemscript** (hex, optional): the redeemscript, only if it's p2sh-wrapped

  If **status** is "confirmed":

    - **blockheight** (u32): Block height where it was confirmed

  If **reserved** is "true":

    - **reserved\_to\_block** (u32): Block height where reservation will expire
- **channels** (array of objects):
  - **peer\_id** (pubkey): the peer with which the channel is opened
  - **our\_amount\_msat** (msat): available satoshis on our node's end of the channel
  - **amount\_msat** (msat): total channel value
  - **funding\_txid** (txid): funding transaction id
  - **funding\_output** (u32): the 0-based index of the output in the funding transaction
  - **connected** (boolean): whether the channel peer is connected
  - **state** (string): the channel state, in particular "CHANNELD\_NORMAL" means the channel can be used normally (one of "OPENINGD", "CHANNELD\_AWAITING\_LOCKIN", "CHANNELD\_NORMAL", "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN", "ONCHAIN", "DUALOPEND\_OPEN\_INIT", "DUALOPEND\_AWAITING\_LOCKIN")

  If **state** is "CHANNELD\_NORMAL":

    - **short\_channel\_id** (short\_channel\_id): short channel id of channel

  If **state** is "CHANNELD\_SHUTTING\_DOWN", "CLOSINGD\_SIGEXCHANGE", "CLOSINGD\_COMPLETE", "AWAITING\_UNILATERAL", "FUNDING\_SPEND\_SEEN" or "ONCHAIN":

    - **short\_channel\_id** (short\_channel\_id, optional): short channel id of channel (only if funding reached lockin depth before closing)

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Felix <<fixone@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-newaddr(7), lightning-fundchannel(7), lightning-withdraw(7), lightning-listtransactions(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:5c118dc7780049bcd320aa16d301bf778552fe6ae42c9d598a3926ab0c14694d)
