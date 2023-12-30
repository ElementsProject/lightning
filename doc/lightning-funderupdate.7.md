lightning-funderupdate -- Command for adjusting node funding v2 channels
========================================================================

SYNOPSIS
--------

**funderupdate** [*policy*] [*policy\_mod*] [*leases\_only*] [*min\_their\_funding\_msat*] [*max\_their\_funding\_msat*] [*per\_channel\_min\_msat*] [*per\_channel\_max\_msat*] [*reserve\_tank\_msat*] [*fuzz\_percent*] [*fund\_probability*] [*lease\_fee\_base\_msat*] [*lease\_fee\_basis*] [*funding\_weight*] [*channel\_fee\_max\_base\_msat*] [*channel\_fee\_max\_proportional\_thousandths*] [*compact\_lease*]

NOTE: Must have --experimental-dual-fund enabled for these settings to take effect.

DESCRIPTION
-----------

For channel open requests using


*policy*, *policy\_mod* is the policy the funder plugin will use to decide
how much capital to commit to a v2 open channel request. There are three
policy options, detailed below: `match`, `available`, and `fixed`.
The *policy\_mod* is the number or 'modification' to apply to the policy.
Default is (fixed, 0sats).

* `match` -- Contribute *policy\_mod* percent of their requested funds.
   Valid *policy\_mod* values are 0 to 200. If this is a channel lease
   request, we match based on their requested funds. If it is not a
   channel lease request (and *lease\_only* is false), then we match
   their funding amount. Note: any lease match less than 100 will
   likely fail, as clients will not accept a lease less than their request.
* `available` -- Contribute *policy\_mod* percent of our available
   node wallet funds. Valid *policy\_mod* values are 0 to 100.
* `fixed` -- Contributes a fixed  *policy\_mod* sats to v2 channel open requests.

Note: to maximize channel leases, best policy setting is (match, 100).

*leases\_only* will only contribute funds to `option_will_fund` requests
which pay to lease funds. Defaults to false, will fund any v2 open request
using *policy* even if it's they're not seeking to lease funds. Note that
`option_will_fund` commits funds for 4032 blocks (~1mo). Must also set
*lease\_fee\_base\_msat*, *lease\_fee\_basis*, *funding\_weight*,
*channel\_fee\_max\_base\_msat*, and *channel\_fee\_max\_proportional\_thousandths*
to advertise available channel leases.

*min\_their\_funding\_msat* is the minimum funding sats that we require in order
to activate our contribution policy to the v2 open.  Defaults to 10k sats.

*max\_their\_funding\_msat* is the maximum funding sats that we will consider
to activate our contribution policy to the v2 open. Any channel open above this
will not be funded.  Defaults to no max (`UINT_MAX`).

*per\_channel\_min\_msat* is the minimum amount that we will contribute to a
channel open. Defaults to 10k sats.

*per\_channel\_max\_msat* is the maximum amount that we will contribute to a
channel open. Defaults to no max (`UINT_MAX`).

*reserve\_tank\_msat* is the amount of sats to leave available in the node wallet.
Defaults to zero sats.

*fuzz\_percent* is a percentage to fuzz the resulting contribution amount by.
Valid values are 0 to 100. Note that turning this on with (match, 100) policy
will randomly fail `option_will_fund` leases, as most clients
expect an exact or greater match of their `requested_funds`.
Defaults to 0% (no fuzz).

*fund\_probability* is the percent of v2 channel open requests to apply our
policy to. Valid values are integers from 0 (fund 0% of all open requests)
to 100 (fund every request). Useful for randomizing opens that receive funds.
Defaults to 100.

Setting any of the next 5 options will activate channel leases for this node,
and advertise these values via the lightning gossip network. If any one is set,
the other values will be the default.

*lease\_fee\_base\_msat* is the flat fee for a channel lease. Node will
receive this much extra added to their channel balance, paid by the opening
node. Defaults to 2k sats. Note that the minimum is 1sat.

*lease\_fee\_basis* is a basis fee that's calculated as 1/10k of the total
requested funds the peer is asking for. Node will receive the total of
*lease\_fee\_basis* times requested funds / 10k satoshis added to their channel
balance, paid by the opening node.  Default is 0.65% (65 basis points)

*funding\_weight* is used to calculate the fee the peer will compensate your
node for its contributing inputs to the funding transaction. The total fee
is calculated as the `open_channel2`.`funding_feerate_perkw` times this
*funding\_weight* divided by 1000. Node will have this funding fee added
to their channel balance, paid by the opening node.  Default is
2 inputs + 1 P2WPKH output.

*channel\_fee\_max\_base\_msat* is a commitment to a maximum
`channel_fee_base_msat` that your node will charge for routing payments
over this leased channel during the lease duration.  Default is 5k sats.

*channel\_fee\_max\_proportional\_thousandths* is a commitment to a maximum
`channel_fee_proportional_millionths` that your node will charge for
routing payments over this leased channel during the lease duration.
Note that it's denominated in 'thousandths'. A setting of `1` is equal
to 1k ppm; `5` is 5k ppm, etc.  Default is 100 (100k ppm).

*compact\_lease* is a compact description of the channel lease params. When
opening a channel, passed in to `fundchannel` to indicate the terms we
expect from the peer.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **summary** (string): Summary of the current funding policy e.g. (match 100)
- **policy** (string): Policy funder plugin will use to decide how much capital to commit to a v2 open channel request (one of "match", "available", "fixed")
- **policy\_mod** (u32): The *policy\_mod* is the number or 'modification' to apply to the policy.
- **leases\_only** (boolean): Only contribute funds to `option_will_fund` lease requests.
- **min\_their\_funding\_msat** (msat): The minimum funding sats that we require from peer to activate our funding policy.
- **max\_their\_funding\_msat** (msat): The maximum funding sats that we'll allow from peer to activate our funding policy.
- **per\_channel\_min\_msat** (msat): The minimum amount that we will fund a channel open with.
- **per\_channel\_max\_msat** (msat): The maximum amount that we will fund a channel open with.
- **reserve\_tank\_msat** (msat): Amount of sats to leave available in the node wallet.
- **fuzz\_percent** (u32): Percentage to fuzz our funding amount by.
- **fund\_probability** (u32): Percent of opens to consider funding. 100 means we'll consider funding every requested open channel request.
- **lease\_fee\_base\_msat** (msat, optional): Flat fee to charge for a channel lease.
- **lease\_fee\_basis** (u32, optional): Proportional fee to charge for a channel lease, calculated as 1/10,000th of requested funds.
- **funding\_weight** (u32, optional): Transaction weight the channel opener will pay us for a leased funding transaction.
- **channel\_fee\_max\_base\_msat** (msat, optional): Maximum channel\_fee\_base\_msat we'll charge for routing funds leased on this channel.
- **channel\_fee\_max\_proportional\_thousandths** (u32, optional): Maximum channel\_fee\_proportional\_millitionths we'll charge for routing funds leased on this channel, in thousandths.
- **compact\_lease** (hex, optional): Compact description of the channel lease parameters.

[comment]: # (GENERATE-FROM-SCHEMA-END)

The following error code may occur:

- -32602: If the given parameters are invalid.

AUTHOR
------

@niftynei <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-fundchannel(7), lightning-listfunds(7)


RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:64262de96cbce3ee1914ffed90e5a5112c2448703406e33c0056790e6ed68320)
