lightning-reserveinputs -- Construct a transaction and reserve the UTXOs it spends
==================================================================================

SYNOPSIS
--------

**reserveinputs** *psbt* [*exclusive*]

DESCRIPTION
-----------

The **reserveinputs** RPC command places (or increases) reservations on any
inputs specified in *psbt* which are known to lightningd.  It will fail
with an error if any of the inputs are known to be spent, and ignore inputs
which are unknown.

Normally the command will fail (with no reservations made) if an input
is already reserved.  If *exclusive* is set to *False*, then existing
reservations are simply extended, rather than causing failure.


RETURN VALUE
------------

On success, a *reservations* array is returned, with an entry for each input
which was reserved:

- *txid* is the input transaction id.
- *vout* is the input index.
- *was_reserved* indicates whether the input was already reserved.
- *reserved* indicates that the input is now reserved (i.e. true).
- *reserved_to_block* indicates what blockheight the reservation will expire.

On failure, an error is reported and no UTXOs are reserved.

The following error codes may occur:
- -32602: Invalid parameter, such as specifying a spent/reserved input in *psbt*.

AUTHOR
------

niftynei <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-unreserveinputs(7), lightning-signpsbt(7), lightning-sendpsbt(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
