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
- **was\_reserved** (boolean): whether the input was already reserved (usually `true`)
- **reserved** (boolean): whether the input is now reserved (may still be `true` if it was reserved for a long time)

If **reserved** is *true*:

  - **reserved\_to\_block** (u32): what blockheight the reservation will expire

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

[comment]: # ( SHA256STAMP:2957a85bf8b9d70f8e253d6646f31aa9c2f135c7a161fd52d0e86d933adc3c57)
