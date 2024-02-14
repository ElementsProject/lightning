lightning-listhtlcs -- Command for querying HTLCs
=================================================

SYNOPSIS
--------

**listhtlcs** [*id*] 

DESCRIPTION
-----------

The **listhtlcs** RPC command gets all HTLCs (which, generally, we remember for as long as a channel is open, even if they've completed long ago).

- **id** (string, optional): A short channel id (e.g. 1x2x3) or full 64-byte hex channel id, it will only list htlcs for that channel (which must be known).

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listhtlcs#1",
  "method": "listhtlcs",
  "params": "{}"
}
{
  "id": "example:listhtlcs#2",
  "method": "listhtlcs",
  "params": [
    "103x2x0"
  ]
}
{
  "id": "example:listhtlcs#3",
  "method": "listhtlcs",
  "params": [
    "436c2658eb4f4689b42ff11b8b05f31ba09860d0df7168085e0796cdf40f85e0"
  ]
}
```

RETURN VALUE
------------

On success, an object containing **htlcs** is returned. It is an array of objects, where each object contains:

- **short\_channel\_id** (short\_channel\_id): The channel that contains/contained the HTLC.
- **id** (u64): The unique, incrementing HTLC id the creator gave this.
- **expiry** (u32): The block number where this HTLC expires/expired.
- **amount\_msat** (msat): The value of the HTLC.
- **direction** (string) (one of "out", "in"): Out if we offered this to the peer, in if they offered it.
- **payment\_hash** (hash): Payment hash sought by HTLC.
- **state** (string) (one of "SENT\_ADD\_HTLC", "SENT\_ADD\_COMMIT", "RCVD\_ADD\_REVOCATION", "RCVD\_ADD\_ACK\_COMMIT", "SENT\_ADD\_ACK\_REVOCATION", "RCVD\_REMOVE\_HTLC", "RCVD\_REMOVE\_COMMIT", "SENT\_REMOVE\_REVOCATION", "SENT\_REMOVE\_ACK\_COMMIT", "RCVD\_REMOVE\_ACK\_REVOCATION", "RCVD\_ADD\_HTLC", "RCVD\_ADD\_COMMIT", "SENT\_ADD\_REVOCATION", "SENT\_ADD\_ACK\_COMMIT", "RCVD\_ADD\_ACK\_REVOCATION", "SENT\_REMOVE\_HTLC", "SENT\_REMOVE\_COMMIT", "RCVD\_REMOVE\_REVOCATION", "RCVD\_REMOVE\_ACK\_COMMIT", "SENT\_REMOVE\_ACK\_REVOCATION"): The first 10 states are for `in`, the next 10 are for `out`.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "htlcs": [
    {
      "short_channel_id": "103x1x0",
      "id": 0,
      "expiry": 117,
      "direction": "out",
      "amount_msat": 100001001,
      "payment_hash": "d2668e77c5a2220496e813de36f1fc09ba804b16af4c6bb38299d8a6eb8a5f10",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    },
    {
      "short_channel_id": "103x1x0",
      "id": 1,
      "expiry": 117,
      "direction": "out",
      "amount_msat": 100001001,
      "payment_hash": "286e08ac8f575f10508d751fcfc93871b4344271967c7b9e5eacb3f3573b8307",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    },
    {
      "short_channel_id": "103x1x0",
      "id": 2,
      "expiry": 135,
      "direction": "out",
      "amount_msat": 100001001,
      "payment_hash": "3e4baa750ee3dfb934578f041ccb40b87432bf37ec65c9d7bce5ff28fecbd95f",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    },
    {
      "short_channel_id": "103x1x0",
      "id": 3,
      "expiry": 135,
      "direction": "out",
      "amount_msat": 100001001,
      "payment_hash": "4c3ce32565dc10ef2bd230c32802ce2fe8b007208c0a90757aa289f75c994d49",
      "state": "SENT_REMOVE_REVOCATION"
    }
  ]
}
{
  "htlcs": [
    {
      "short_channel_id": "103x2x0",
      "id": 0,
      "expiry": 117,
      "direction": "out",
      "amount_msat": 100001001,
      "payment_hash": "12bb14b1d119e1ae0759e5ff6f1f6653e3fd8f71ea59411500d2871404a47a98",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    },
    {
      "short_channel_id": "103x2x0",
      "id": 1,
      "expiry": 117,
      "direction": "out",
      "amount_msat": 100001001,
      "payment_hash": "57d950209cc0b4fcc5e3027569232f96cf83ef85314c6b139a5713848d811a66",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    },
    {
      "short_channel_id": "103x2x0",
      "id": 2,
      "expiry": 135,
      "direction": "out",
      "amount_msat": 100001001,
      "payment_hash": "45ad4654715411a07a0ad6ec3f4bfaa918c90e3d1934b10b1c1c5846523ddd7f",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    },
    {
      "short_channel_id": "103x2x0",
      "id": 3,
      "expiry": 135,
      "direction": "out",
      "amount_msat": 100001001,
      "payment_hash": "cc0dcd214aa71c62bfba711a0746da821f2cdba1770b11c225920bdde12c931e",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    }
  ]
}
{
  "htlcs": [
    {
      "short_channel_id": "103x1x0",
      "id": 0,
      "expiry": 124,
      "direction": "out",
      "amount_msat": 1001,
      "payment_hash": "2ab653668c8017ff2f36ac36678a8da04e11380bd9580a2926b170523b0c6e3b",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    },
    {
      "short_channel_id": "103x1x0",
      "id": 1,
      "expiry": 124,
      "direction": "out",
      "amount_msat": 2001,
      "payment_hash": "92f889cb2e48aa28e1e577228b907cdbcc371a2c018e9c8f60fa7036e232cf1d",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    },
    {
      "short_channel_id": "103x1x0",
      "id": 2,
      "expiry": 128,
      "direction": "out",
      "amount_msat": 4001,
      "payment_hash": "14ef01c9fb12d7dcac288f48ce87b19a7d5c3d5779aaed1e4adcb5c5d0e9fa45",
      "state": "RCVD_REMOVE_ACK_REVOCATION"
    }
  ]
}
```

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listforwards(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
