lightning-reserveinputs -- Construct a transaction and reserve the UTXOs it spends
==================================================================================

SYNOPSIS
--------

**reserveinputs** *psbt* [*exclusive*] [*reserve*]

DESCRIPTION
-----------

The **reserveinputs** RPC command places (or increases) reservations on any
inputs specified in *psbt* which are known to lightningd.  It will fail
with an error if any of the inputs are known to be spent, and ignore inputs
which are unknown.

Normally the command will fail (with no reservations made) if an input
is already reserved.  If *exclusive* is set to *False*, then existing
reservations are simply extended, rather than causing failure.

By default, reservations are for the next 72 blocks (approximately 6
hours), but this can be changed by setting *reserve*.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **reservations** is returned.  It is an array of objects, where each object contains:

- **txid** (txid): the transaction id
- **vout** (u32): the output number which was reserved
- **was\_reserved** (boolean): whether the input was already reserved
- **reserved** (boolean): whether the input is now reserved (always *true*)
- **reserved\_to\_block** (u32): what blockheight the reservation will expire

[comment]: # (GENERATE-FROM-SCHEMA-END)

On success, a *reservations* array is returned, with an entry for each input
which was reserved:

- *txid* is the input transaction id.
- *vout* is the input index.
- *was\_reserved* indicates whether the input was already reserved.
- *reserved* indicates that the input is now reserved (i.e. true).
- *reserved\_to\_block* indicates what blockheight the reservation will expire.

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

[comment]: # ( SHA256STAMP:ca50532790e2f80730b6ec6f066cee5a1e57867548fd36503e8faebc16a205b5)
