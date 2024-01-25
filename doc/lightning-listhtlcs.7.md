lightning-listhtlcs -- Command for querying HTLCs
=================================================

SYNOPSIS
--------

**listhtlcs** [*id*]

DESCRIPTION
-----------

The **listhtlcs** RPC command gets all HTLCs (which, generally, we
remember for as long as a channel is open, even if they've completed
long ago).  If given a short channel id (e.g. 1x2x3) or full 64-byte
hex channel id, it will only list htlcs for that channel (which
must be known).

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **htlcs** is returned.  It is an array of objects, where each object contains:

- **short\_channel\_id** (short\_channel\_id): the channel that contains/contained the HTLC
- **id** (u64): the unique, incrementing HTLC id the creator gave this
- **expiry** (u32): the block number where this HTLC expires/expired
- **amount\_msat** (msat): the value of the HTLC
- **direction** (string): out if we offered this to the peer, in if they offered it (one of "out", "in")
- **payment\_hash** (hash): payment hash sought by HTLC
- **state** (string): The first 10 states are for `in`, the next 10 are for `out`. (one of "SENT\_ADD\_HTLC", "SENT\_ADD\_COMMIT", "RCVD\_ADD\_REVOCATION", "RCVD\_ADD\_ACK\_COMMIT", "SENT\_ADD\_ACK\_REVOCATION", "RCVD\_REMOVE\_HTLC", "RCVD\_REMOVE\_COMMIT", "SENT\_REMOVE\_REVOCATION", "SENT\_REMOVE\_ACK\_COMMIT", "RCVD\_REMOVE\_ACK\_REVOCATION", "RCVD\_ADD\_HTLC", "RCVD\_ADD\_COMMIT", "SENT\_ADD\_REVOCATION", "SENT\_ADD\_ACK\_COMMIT", "RCVD\_ADD\_ACK\_REVOCATION", "SENT\_REMOVE\_HTLC", "SENT\_REMOVE\_COMMIT", "RCVD\_REMOVE\_REVOCATION", "RCVD\_REMOVE\_ACK\_COMMIT", "SENT\_REMOVE\_ACK\_REVOCATION")

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listforwards(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:e787b9ea6bee54252239ba2f2b7220f5f3c79b2932c0b5a9ea255fbf1b14cf55)
