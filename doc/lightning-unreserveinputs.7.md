lightning-unreserveinputs -- Release reserved UTXOs
===================================================

SYNOPSIS
--------

**unreserveinputs** *psbt* [*reserve*]

DESCRIPTION
-----------

The **unreserveinputs** RPC command releases (or reduces reservation)
on UTXOs which were previously marked as reserved, generally by
lightning-reserveinputs(7).

The inputs to unreserve are the inputs specified in the passed-in *psbt*.

If *reserve* is specified, it is the number of blocks to decrease
reservation by; default is 72.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **reservations** is returned.  It is an array of objects, where each object contains:
- **txid** (txid): the transaction id
- **vout** (u32): the output number which was reserved
- **was_reserved** (boolean): whether the input was already reserved (usually `true`)
- **reserved** (boolean): whether the input is now reserved (may still be `true` if it was reserved for a long time)

If **reserved** is *true*:
  - **reserved_to_block** (u32): what blockheight the reservation will expire

[comment]: # (GENERATE-FROM-SCHEMA-END)

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

[comment]: # ( SHA256STAMP:f7aca3e1a40d66e07986cb9e98033e815c4eea2237dc75664a6c47951a8132ed)
