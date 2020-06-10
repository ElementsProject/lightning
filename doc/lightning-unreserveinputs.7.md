lightning-unreserveinputs -- Release reserved UTXOs
===================================================

SYNOPSIS
--------

**unreserveinputs** *psbt*

DESCRIPTION
-----------

The **unreserveinputs** RPC command releases UTXOs which were previously 
marked as reserved, generally by lightning-reserveinputs(7).

The inputs to unreserve are the inputs specified in the passed-in *psbt*.

RETURN VALUE
------------

On success, an object with *outputs* will be returned.

*outputs* will include an entry for each input specified in the *psbt*,
indicating the *txid* and *vout* for that input plus a boolean result
 *unreserved*, which will be true if that UTXO was successfully unreserved
by this call.

Note that restarting lightningd will unreserve all UTXOs by default.

The following error codes may occur:
- -1: An unparseable PSBT.

AUTHOR
------

niftynei <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-unreserveinputs(7), lightning-signpsbt(7), lightning-sendpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
