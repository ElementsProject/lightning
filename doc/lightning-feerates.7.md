lightning-feerates -- Command for querying recommended onchain feerates
=======================================================================

SYNOPSIS
--------

**feerates** *style*

DESCRIPTION
-----------

The **feerates** command returns the feerates that C-lightning will use.
The feerates will be based on the recommended feerates from the backend.
The backend may fail to provide estimates, but if it was able to provide
estimates in the past, C-lightning will continue to use those for a while.
C-lightning will also smoothen feerate estimations from the backend.

*style* is either of the two strings:

* *perkw* - provide feerate in units of satoshis per 1000 weight.
* *perkb* - provide feerate in units of satoshis per 1000 virtual bytes.

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
  - **min_acceptable** (u32): The smallest feerate that you can use, usually the minimum relayed feerate of the backend
  - **max_acceptable** (u32): The largest feerate we will accept from remote negotiations.  If a peer attempts to set the feerate higher than this we will unilaterally close the channel (or simply forget it if it's not open yet).
  - **opening** (u32, optional): Default feerate for lightning-fundchannel(7) and lightning-withdraw(7)
  - **mutual_close** (u32, optional): Feerate to aim for in cooperative shutdown.  Note that since mutual close is a **negotiation**, the actual feerate used in mutual close will be somewhere between this and the corresponding mutual close feerate of the peer.
  - **unilateral_close** (u32, optional): Feerate for commitment_transaction in a live channel which we originally funded
  - **delayed_to_us** (u32, optional): Feerate for returning unilateral close funds to our wallet
  - **htlc_resolution** (u32, optional): Feerate for returning unilateral close HTLC outputs to our wallet
  - **penalty** (u32, optional): Feerate to start at when penalizing a cheat attempt
- **perkw** (object, optional): If *style* parameter was perkw:
  - **min_acceptable** (u32): The smallest feerate that you can use, usually the minimum relayed feerate of the backend
  - **max_acceptable** (u32): The largest feerate we will accept from remote negotiations.  If a peer attempts to set the feerate higher than this we will unilaterally close the channel (or simply forget it if it's not open yet).
  - **opening** (u32, optional): Default feerate for lightning-fundchannel(7) and lightning-withdraw(7)
  - **mutual_close** (u32, optional): Feerate to aim for in cooperative shutdown.  Note that since mutual close is a **negotiation**, the actual feerate used in mutual close will be somewhere between this and the corresponding mutual close feerate of the peer.
  - **unilateral_close** (u32, optional): Feerate for commitment_transaction in a live channel which we originally funded
  - **delayed_to_us** (u32, optional): Feerate for returning unilateral close funds to our wallet
  - **htlc_resolution** (u32, optional): Feerate for returning unilateral close HTLC outputs to our wallet
  - **penalty** (u32, optional): Feerate to start at when penalizing a cheat attempt
- **onchain_fee_estimates** (object, optional):
  - **opening_channel_satoshis** (u64): Estimated cost of typical channel open
  - **mutual_close_satoshis** (u64): Estimated cost of typical channel close
  - **unilateral_close_satoshis** (u64): Estimated cost of typical unilateral close (without HTLCs)
  - **htlc_timeout_satoshis** (u64): Estimated cost of typical HTLC timeout transaction
  - **htlc_success_satoshis** (u64): Estimated cost of typical HTLC fulfillment transaction

The following warnings may also be returned:
- **warning_missing_feerates**: Some fee estimates are missing

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The **feerates** command will never error,
however some fields may be missing in the result
if feerate estimates for that kind of transaction are unavailable.

NOTES
-----

Many other commands have a *feerate* parameter, which can be the strings
*urgent*, *normal*, or *slow*.
These are mapped to the **feerates** outputs as:

* *urgent* - equal to *unilateral\_close*
* *normal* - equal to *opening*
* *slow* - equal to *min\_acceptable*.

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
lightning-txprepare(7), lightning-fundchannel_start(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:8fe321fcba7b3a471f4f83f98638dbc820fc0abe91f3d53ca55fdb0222e17a8d)
