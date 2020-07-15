lightning-unreserveinputs -- Release reserved UTXOs
===================================================

SYNOPSIS
--------

**unreserveinputs** *psbt*

DESCRIPTION
-----------

The **unreserveinputs** RPC command releases (or reduces reservation)
on UTXOs which were previously marked as reserved, generally by
lightning-reserveinputs(7).

The inputs to unreserve are the inputs specified in the passed-in *psbt*.

RETURN VALUE
------------

On success, an *reservations* array is returned, with an entry for each input
which was reserved:

- *txid* is the input transaction id.
- *vout* is the input index.
- *was_reserved* indicates whether the input was already reserved (generally true)
- *reserved* indicates that the input is now reserved (may still be true, if it was previously reserved for a long time).
- *reserved_to_block* (if *reserved* is still true) indicates what blockheight the reservation will expire.

On failure, an error is reported and no UTXOs are unreserved.

The following error codes may occur:
- -32602: Invalid parameter, i.e. an unparseable PSBT.

AUTHOR
------

niftynei <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-unreserveinputs(7), lightning-signpsbt(7), lightning-sendpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
