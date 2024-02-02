lightning-funderupdate -- Command for adjusting node funding v2 channels
========================================================================

SYNOPSIS
--------

**funderupdate** [*policy*] [*policy\_mod*] [*leases\_only*] [*min\_their\_funding\_msat*] [*max\_their\_funding\_msat*] [*per\_channel\_min\_msat*] [*per\_channel\_max\_msat*] [*reserve\_tank\_msat*] [*fuzz\_percent*] [*fund\_probability*] [*lease\_fee\_base\_msat*] [*lease\_fee\_basis*] [*funding\_weight*] [*channel\_fee\_max\_base\_msat*] [*channel\_fee\_max\_proportional\_thousandths*] [*compact\_lease*]


DESCRIPTION
-----------

NOTE: Must have --experimental-dual-fund enabled for these settings to take effect.

For channel open requests using dual funding.

Note: to maximize channel leases, best policy setting is (match, 100).

Setting any of the 5 options from *lease_fee_base_msat*, *lease_fee_basis*, *funding_weight*, *channel_fee_max_base_msat* and, *channel_fee_max_proportional_thousandths* will activate channel leases for this node, and advertise these values via the lightning gossip network. If any one is set, the other values will be the default.

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

ERRORS
------

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
