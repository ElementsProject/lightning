lightning-listclosedchannels -- Get data on our closed historical channels
==========================================================================

SYNOPSIS
--------

**listclosedchannels** \[*id*\]

DESCRIPTION
-----------

The **listclosedchannels** RPC command returns data on channels which
are otherwise forgotten (more than 100 blocks after they're completely
resolved onchain).

If no *id* is supplied, then channel data on all historical channels are given.

Supplying *id* will filter the results to only match channels to that peer.  Note that prior to v23.05, old peers were forgotten.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **closedchannels** is returned.  It is an array of objects, where each object contains:

- **channel\_id** (hash): The full channel\_id (funding txid Xored with output number)
- **opener** (string): Who initiated the channel (one of "local", "remote")
- **private** (boolean): if False, we will not announce this channel
- **total\_local\_commitments** (u64): Number of commitment transaction we made
- **total\_remote\_commitments** (u64): Number of commitment transaction they made
- **total\_htlcs\_sent** (u64): Number of HTLCs we ever sent
- **funding\_txid** (txid): ID of the funding transaction
- **funding\_outnum** (u32): The 0-based output number of the funding transaction which opens the channel
- **leased** (boolean): Whether this channel was leased from `opener`
- **total\_msat** (msat): total amount in the channel
- **final\_to\_us\_msat** (msat): Our balance in final commitment transaction
- **min\_to\_us\_msat** (msat): Least amount owed to us ever.  If the peer were to succesfully steal from us, this is the amount we would still retain.
- **max\_to\_us\_msat** (msat): Most amount owed to us ever.  If we were to successfully steal from the peer, this is the amount we could potentially get.
- **close\_cause** (string): What caused the channel to close (one of "unknown", "local", "user", "remote", "protocol", "onchain")
- **peer\_id** (pubkey, optional): Peer public key (can be missing with pre-v23.05 closes!)
- **short\_channel\_id** (short\_channel\_id, optional): The short\_channel\_id
- **alias** (object, optional):
  - **local** (short\_channel\_id, optional): An alias assigned by this node to this channel, used for outgoing payments
  - **remote** (short\_channel\_id, optional): An alias assigned by the remote node to this channel, usable in routehints and invoices
- **closer** (string, optional): Who initiated the channel close (only present if closing) (one of "local", "remote")
- **channel\_type** (object, optional): channel\_type as negotiated with peer:
  - **bits** (array of u32s): Each bit set in this channel\_type:
    - Bit number
  - **names** (array of strings): Feature name for each bit set in this channel\_type:
    - Name of feature bit (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even")
- **funding\_fee\_paid\_msat** (msat, optional): How much we paid to lease the channel (iff `leased` is true and `opener` is local)
- **funding\_fee\_rcvd\_msat** (msat, optional): How much they paid to lease the channel (iff `leased` is true and `opener` is remote)
- **funding\_pushed\_msat** (msat, optional): How much `opener` pushed immediate (if non-zero)
- **last\_commitment\_txid** (hash, optional): The final commitment tx's txid (or mutual close, if we accepted it).  Not present for some very old, small channels pre-0.7.0.
- **last\_commitment\_fee\_msat** (msat, optional): The fee on `last_commitment_txid`

[comment]: # (GENERATE-FROM-SCHEMA-END)

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.

AUTHOR
------

Rusty Russell <<rusty@blockstream.com>>.

SEE ALSO
--------

lightning-listpeerchannels(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning> Lightning

[comment]: # ( SHA256STAMP:0c368cb41f46a2124e9b3f0b760494d1f4b9c3b248267f56b887fbf96f26e176)
