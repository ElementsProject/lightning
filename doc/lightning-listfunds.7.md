lightning-listfunds -- Command showing all funds currently managed by the c-lightning node
==========================================================================================

SYNOPSIS
--------

**listfunds** \[*spent*\]

DESCRIPTION
-----------

The **listfunds** RPC command displays all funds available, either in
unspent outputs (UTXOs) in the internal wallet or funds locked in
currently open channels.

*spent* is a boolean: if true, then the *outputs* will include spent outputs
in addition to the unspent ones. Default is false.

RETURN VALUE
------------

On success two arrays will be returned: *outputs* with funds currently
locked onchain in UTXOs and *channels* with funds readily spendable in
channels.

Each entry in *outputs* will include:
-   *txid*
-   *output* (the index of the output in the transaction)
-   *value* (the output value in satoshis)
-   *amount\_msat* (the same as *value*, but in millisatoshi with *msat*
    appended)
-   *address*
-   *scriptpubkey* (the ScriptPubkey of the output, in hex)
-   *redeemscript* (the redeemscript of the output, in hex, only if it's p2sh-wrapped)
-   *status* (whether *unconfirmed*, *confirmed*, or *spent*)
-   *reserved* (whether this is UTXO is currently reserved for an in-flight tx)
-   *reserved_to_block* (when reservation expires, if *reserved* is true)

Each entry in *channels* will include:
-   *peer\_id* - the peer with which the channel is opened.
-   *short\_channel\_id* - as per BOLT 7 (representing the block,
    transaction number and output index of the channel funding
    transaction).
-   *channel\_sat* - available satoshis on our node’s end of the channel
    (values rounded down to satoshis as internal storage is in
    millisatoshi).
-   *our\_amount\_msat* - same as above, but in millisatoshis with
    *msat* appended.
-   *channel\_total\_sat* - total channel value in satoshi
-   *amount\_msat* - same as above, but in millisatoshis with *msat*
    appended.
-   *funding\_txid* - funding transaction id.
-   *funding\_output* - the index of the output in the funding
    transaction.
-   *connected* - whether the channel peer is connected.
-   *state* - the channel state, in particular *CHANNELD_NORMAL* means the
    channel can be used normally.

AUTHOR
------

Felix <<fixone@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-newaddr(7), lightning-fundchannel(7), lightning-withdraw(7), lightning-listtransactions(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

