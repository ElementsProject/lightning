lightning-listforwards -- Command showing all htlcs and their information
=========================================================================

SYNOPSIS
--------

**listforwards** [*status*] [*in_channel*] [*out_channel*]

DESCRIPTION
-----------

The **listforwards** RPC command displays all htlcs that have been
attempted to be forwarded by the c-lightning node.

If *status* is specified, then only the forwards with the given status are returned.
*status* can be either *offered* or *settled* or *failed* or *local_failed*

If *in_channel* or *out_channel* is specified, then only the matching forwards
on the given in/out channel are returned.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **forwards** is returned.  It is an array of objects, where each object contains:
- **in_channel** (short_channel_id): the channel that received the HTLC
- **in_msat** (msat): the value of the incoming HTLC
- **status** (string): still ongoing, completed, failed locally, or failed after forwarding (one of "offered", "settled", "local_failed", "failed")
- **received_time** (number): the UNIX timestamp when this was received
- **out_channel** (short_channel_id, optional): the channel that the HTLC was forwarded to
- **payment_hash** (hex, optional): payment hash sought by HTLC (always 64 characters)

If **out_channel** is present:
  - **fee_msat** (msat): the amount this paid in fees
  - **out_msat** (msat): the amount we sent out the *out_channel*

If **status** is "settled" or "failed":
  - **resolved_time** (number): the UNIX timestamp when this was resolved

If **status** is "local_failed" or "failed":
  - **failcode** (u32, optional): the numeric onion code returned
  - **failreason** (string, optional): the name of the onion code returned

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rene Pickhardt <<r.pickhardt@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-getinfo(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:abfaaa00817734d8acb77d02d7c024112c90605a8f93a134971a617ab4d383f9)
