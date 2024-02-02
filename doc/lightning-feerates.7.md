lightning-feerates -- Command for querying recommended onchain feerates
=======================================================================

SYNOPSIS
--------

**feerates** *style*

DESCRIPTION
-----------

The **feerates** command returns the feerates that CLN will use.
The feerates will be based on the recommended feerates from the backend.
The backend may fail to provide estimates, but if it was able to provide
estimates in the past, CLN will continue to use those for a while.
CLN will also smoothen feerate estimations from the backend.

Explorers often present fees in "sat/vB": 4 sat/vB is `4000perkb` or
`1000perkw`.

Bitcoin transactions have non-witness and witness bytes:

* Non-witness bytes count as 4 weight, 1 virtual byte.
  All bytes other than SegWit witness count as non-witness bytes.
* Witness bytes count as 1 weight, 0.25 virtual bytes.

Thus, all *perkb* feerates will be exactly 4 times *perkw* feerates.

To compute the fee for a transaction, multiply its weight or virtual bytes
by the appropriate *perkw* or *perkw* feerate
returned by this command,
then divide by 1000.

There is currently no way to change these feerates from the RPC.
If you need custom control over onchain feerates,
you will need to provide your own plugin
that replaces the `bcli` plugin backend.
For commands like lightning-withdraw(7) or lightning-fundchannel(7) you
can provide a preferred feerate directly as a parameter,
which will override the recommended feerates returned by **feerates**.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **perkb** (object, optional): If *style* parameter was perkb:
  - **min\_acceptable** (u32): The smallest feerate that we allow peers to specify: half the 100-block estimate
  - **max\_acceptable** (u32): The largest feerate we will accept from remote negotiations.  If a peer attempts to set the feerate higher than this we will unilaterally close the channel (or simply forget it if it's not open yet).
  - **floor** (u32): The smallest feerate that our backend tells us it will accept (i.e. minrelayfee or mempoolminfee) *(added v23.05)*
  - **estimates** (array of objects): Feerate estimates from plugin which we are using (usuallly bcli) *(added v23.05)*:
    - **blockcount** (u32): The number of blocks the feerate is expected to get a transaction in *(added v23.05)*
    - **feerate** (u32): The feerate for this estimate, in given *style* *(added v23.05)*
    - **smoothed\_feerate** (u32): The feerate, smoothed over time (useful for coordinating with other nodes) *(added v23.05)*
  - **opening** (u32, optional): Default feerate for lightning-fundchannel(7) and lightning-withdraw(7)
  - **mutual\_close** (u32, optional): Feerate to aim for in cooperative shutdown.  Note that since mutual close is a **negotiation**, the actual feerate used in mutual close will be somewhere between this and the corresponding mutual close feerate of the peer.
  - **unilateral\_close** (u32, optional): Feerate for commitment\_transaction in a live channel which we originally funded
  - **unilateral\_anchor\_close** (u32, optional): Feerate for commitment\_transaction in a live channel which we originally funded (if anchor\_outputs was negotiated) *(added v23.08)*
  - **delayed\_to\_us** (u32, optional): Feerate for returning unilateral close funds to our wallet **deprecated in v23.05, removed after v24.05**
  - **htlc\_resolution** (u32, optional): Feerate for returning unilateral close HTLC outputs to our wallet **deprecated in v23.05, removed after v24.05**
  - **penalty** (u32, optional): Feerate to use when creating penalty tx for watchtowers
- **perkw** (object, optional): If *style* parameter was perkw:
  - **min\_acceptable** (u32): The smallest feerate that you can use, usually the minimum relayed feerate of the backend
  - **max\_acceptable** (u32): The largest feerate we will accept from remote negotiations.  If a peer attempts to set the feerate higher than this we will unilaterally close the channel (or simply forget it if it's not open yet).
  - **floor** (u32): The smallest feerate that our backend tells us it will accept (i.e. minrelayfee or mempoolminfee) *(added v23.05)*
  - **estimates** (array of objects): Feerate estimates from plugin which we are using (usuallly bcli) *(added v23.05)*:
    - **blockcount** (u32): The number of blocks the feerate is expected to get a transaction in *(added v23.05)*
    - **feerate** (u32): The feerate for this estimate, in given *style* *(added v23.05)*
    - **smoothed\_feerate** (u32): The feerate, smoothed over time (useful for coordinating with other nodes) *(added v23.05)*
  - **opening** (u32, optional): Default feerate for lightning-fundchannel(7) and lightning-withdraw(7)
  - **mutual\_close** (u32, optional): Feerate to aim for in cooperative shutdown.  Note that since mutual close is a **negotiation**, the actual feerate used in mutual close will be somewhere between this and the corresponding mutual close feerate of the peer.
  - **unilateral\_close** (u32, optional): Feerate for commitment\_transaction in a live channel which we originally funded (if anchor\_outputs was not negotiated)
  - **unilateral\_anchor\_close** (u32, optional): Feerate for commitment\_transaction in a live channel which we originally funded (if anchor\_outputs was negotiated) *(added v23.08)*
  - **delayed\_to\_us** (u32, optional): Feerate for returning unilateral close funds to our wallet **deprecated in v23.05, removed after v24.05**
  - **htlc\_resolution** (u32, optional): Feerate for returning unilateral close HTLC outputs to our wallet **deprecated in v23.05, removed after v24.05**
  - **penalty** (u32, optional): Feerate to use when creating penalty tx for watchtowers
- **onchain\_fee\_estimates** (object, optional):
  - **opening\_channel\_satoshis** (u64): Estimated cost of typical channel open
  - **mutual\_close\_satoshis** (u64): Estimated cost of typical channel close
  - **unilateral\_close\_satoshis** (u64): Estimated cost of typical unilateral close (without HTLCs).  If anchors are supported, this assumes a channel with anchors.
  - **htlc\_timeout\_satoshis** (u64): Estimated cost of typical HTLC timeout transaction (non-anchors)
  - **htlc\_success\_satoshis** (u64): Estimated cost of typical HTLC fulfillment transaction (non-anchors)
  - **unilateral\_close\_nonanchor\_satoshis** (u64, optional): Estimated cost of non-anchor typical unilateral close (without HTLCs). *(added v23.08)*

The following warnings may also be returned:

- **warning\_missing\_feerates**: Some fee estimates are missing

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The **feerates** command will never error,
however some fields may be missing in the result
if feerate estimates for that kind of transaction are unavailable.

NOTES
-----

Many other commands have a *feerate* parameter.  This can be:

* One of the strings to use lightningd's internal estimates:
  * *urgent* (next 6 blocks or so)
  * *normal* (next 12 blocks or so)
  * *slow* (next 100 blocks or so)
  * *minimum* for the lowest value bitcoind will currently accept (added in v23.05)

* A number, with an optional suffix:
  * *blocks* means aim for confirmation in that many blocks (added in v23.05)
  * *perkw* means the number is interpreted as satoshi-per-kilosipa (weight)
  * *perkb* means it is interpreted bitcoind-style as satoshi-per-kilobyte. 
  
Omitting the suffix is equivalent to *perkb*.

TRIVIA
------

In C-lightning we like to call the weight unit "sipa"
in honor of Pieter Wuille,
who uses the name "sipa" on IRC and elsewhere.
Internally we call the *perkw* style as "feerate per kilosipa".

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> wrote the initial version of this
manpage.

SEE ALSO
--------

lightning-parsefeerate(7), lightning-fundchannel(7), lightning-withdraw(7),
lightning-txprepare(7), lightning-fundchannel\_start(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:e0da3f19e5ae27cebe038c1c7c3188405a56bf283ef4d897bf8fb9d63f9b3039)
