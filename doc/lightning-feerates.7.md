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

The **feerates** command returns the feerates in an object named
*perkw* or *perkb*, depending on your *style* parameter.

Some of these estimations may be missing, except for *min\_acceptable*
and *max\_acceptable*, which are always present.

The *perkw* or *perkb* object may have fields containing the estimates:

* *opening* - feerate used for channel opening by lightning-fundchannel(7),
  as well as normal onchain-to-onchain spends by lightning-withdraw(7).
  In general, for all normal onchain-to-onchain spends, this is the feerate
  you should also use.
* *mutual\_close* - the starting feerate used in mutual close negotiation.
  Note that since mutual close is a **negotiation**,
  the actual feerate used in mutual close
  will be somewhere between this
  and the corresponding mutual close feerate of the peer.
* *unilateral\_close* - the feerate we will pay for when a unilateral close
  is done on a channel we originally funded.
  When anchor commitments are implemented,
  this will be the feerate we will use
  for a unilateral close we initiated.
* *delayed\_to\_us* - the feerate we will use when claiming our output from
  a unilateral close we initiated.
* *htlc_resolution* - the feerate we will use to claim HTLCs
  from a unilateral close we initiated.
* *penalty* - the feerate we will use to revoke old state,
  if the counterparty attempts to cheat us.

The following fields are always present in the *perkw* or *perkb* object:

* *min\_acceptable* - the smallest feerate that you can use,
  usually the minimum relayed feerate of the backend.
* *max\_acceptable* - the largest feerate we will accept
  from remote negotiations.
  If a peer attempts to open a channel to us but wants a unilateral close
  feerate larger than *max\_acceptable*, we reject the open attempt.
  If the peer attempts to change the unilateral close feerate of a channel it
  opened to us, such that the new feerate exceeds *max\_acceptable*, we
  unilaterally close the channel
  (at the current unilateral close feerate instead of the new one).

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

ZmnSCPxj < <ZmnSCPxj@protonmail.com> > wrote the initial version of this
manpage.

SEE ALSO
--------

lightning-fundchannel(7), lightning-withdraw(7), lightning-txprepare(7),
lightning-fundchannel_start(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

