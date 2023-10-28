lightning-listforwards -- Command showing all htlcs and their information
=========================================================================

SYNOPSIS
--------

**listforwards** [*status*] [*in\_channel*] [*out\_channel*] [*index* [*start*] [*limit*]]

DESCRIPTION
-----------

The **listforwards** RPC command displays all htlcs that have been
attempted to be forwarded by the Core Lightning node.

If *status* is specified, then only the forwards with the given status are returned.
*status* can be either *offered* or *settled* or *failed* or *local\_failed*

If *in\_channel* or *out\_channel* is specified, then only the matching forwards
on the given in/out channel are returned.

If neither *in\_channel* or *out\_channel* is specified,
`index` controls ordering, by `created` (default) or `updated`.  If
`index` is specified, `start` may be specified to start from that
value, which is generally returned from lightning-wait(7), and `limit`
can be used to specify the maximum number of entries to return.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **forwards** is returned.  It is an array of objects, where each object contains:

- **created\_index** (u64): 1-based index indicating order this forward was created in *(added v23.11)*
- **in\_channel** (short\_channel\_id): the channel that received the HTLC
- **in\_msat** (msat): the value of the incoming HTLC
- **status** (string): still ongoing, completed, failed locally, or failed after forwarding (one of "offered", "settled", "local\_failed", "failed")
- **received\_time** (number): the UNIX timestamp when this was received
- **in\_htlc\_id** (u64, optional): the unique HTLC id the sender gave this (not present if incoming channel was closed before ugprade to v22.11)
- **out\_channel** (short\_channel\_id, optional): the channel that the HTLC (trying to) forward to
- **out\_htlc\_id** (u64, optional): the unique HTLC id we gave this when sending (may be missing even if out\_channel is present, for old forwards before v22.11)
- **updated\_index** (u64, optional): 1-based index indicating order this forward was changed (only present if it has changed since creation) *(added v23.11)*
- **style** (string, optional): Either a legacy onion format or a modern tlv format (one of "legacy", "tlv")

If **out\_msat** is present:

  - **fee\_msat** (msat): the amount this paid in fees
  - **out\_msat** (msat): the amount we sent out the *out\_channel*

If **status** is "settled" or "failed":

  - **resolved\_time** (number): the UNIX timestamp when this was resolved

If **status** is "local\_failed" or "failed":

  - **failcode** (u32, optional): the numeric onion code returned
  - **failreason** (string, optional): the name of the onion code returned

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rene Pickhardt <<r.pickhardt@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-autoclean-status(7), lightning-getinfo(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:b08957fa97a9e574ea80570518551577e272552a29b60d5b1620f00bdfdfe225)
