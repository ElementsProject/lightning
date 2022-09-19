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
- **payment\_hash** (hex): payment hash sought by HTLC (always 64 characters)
- **state** (string): The first 10 states are for `in`, the next 10 are for `out`. (one of "SENT_ADD_HTLC", "SENT_ADD_COMMIT", "RCVD_ADD_REVOCATION", "RCVD_ADD_ACK_COMMIT", "SENT_ADD_ACK_REVOCATION", "RCVD_REMOVE_HTLC", "RCVD_REMOVE_COMMIT", "SENT_REMOVE_REVOCATION", "SENT_REMOVE_ACK_COMMIT", "RCVD_REMOVE_ACK_REVOCATION", "RCVD_ADD_HTLC", "RCVD_ADD_COMMIT", "SENT_ADD_REVOCATION", "SENT_ADD_ACK_COMMIT", "RCVD_ADD_ACK_REVOCATION", "SENT_REMOVE_HTLC", "SENT_REMOVE_COMMIT", "RCVD_REMOVE_REVOCATION", "RCVD_REMOVE_ACK_COMMIT", "SENT_REMOVE_ACK_REVOCATION")

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

[comment]: # ( SHA256STAMP:6ef16f6e1f54522435130d99f224ca41a38fb3c5bc26886ccdaddc69f1abb946)
