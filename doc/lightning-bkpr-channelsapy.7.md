lightning-bkpr-channelsapy -- Command to list stats on channel earnings
==================================================================

SYNOPSIS
--------

**bkpr-channelsapy** \[*start_time*\] \[*end_time*\]

DESCRIPTION
-----------

The **bkpr-channelsapy** RPC command lists stats on routing income, leasing income,
and various calculated APYs for channel routed funds.

The **start_time** is a UNIX timestamp (in seconds) that filters events after the provided timestamp. Defaults to zero.

The **end_time** is a UNIX timestamp (in seconds) that filters events up to and at the provided timestamp. Defaults to max-int.


RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **channels_apy** is returned.  It is an array of objects, where each object contains:
- **account** (string): The account name. If the account is a channel, the channel_id. The 'net' entry is the rollup of all channel accounts
- **routed_out_msat** (msat): Sats routed (outbound)
- **routed_in_msat** (msat): Sats routed (inbound)
- **lease_fee_paid_msat** (msat): Sats paid for leasing inbound (liquidity ads)
- **lease_fee_earned_msat** (msat): Sats earned for leasing outbound (liquidity ads)
- **pushed_out_msat** (msat): Sats pushed to peer at open
- **pushed_in_msat** (msat): Sats pushed in from peer at open
- **our_start_balance_msat** (msat): Starting balance in channel at funding. Note that if our start ballance is zero, any _initial field will be omitted (can't divide by zero)
- **channel_start_balance_msat** (msat): Total starting balance at funding
- **fees_out_msat** (msat): Fees earned on routed outbound
- **utilization_out** (string): Sats routed outbound / total start balance
- **utilization_in** (string): Sats routed inbound / total start balance
- **apy_out** (string): Fees earned on outbound routed payments / total start balance for the length of time this channel has been open amortized to a year (APY)
- **apy_in** (string): Fees earned on inbound routed payments / total start balance for the length of time this channel has been open amortized to a year (APY)
- **apy_total** (string): Total fees earned on routed payments / total start balance for the length of time this channel has been open amortized to a year (APY)
- **fees_in_msat** (msat, optional): Fees earned on routed inbound
- **utilization_out_initial** (string, optional): Sats routed outbound / our start balance
- **utilization_in_initial** (string, optional): Sats routed inbound / our start balance
- **apy_out_initial** (string, optional): Fees earned on outbound routed payments / our start balance for the length of time this channel has been open amortized to a year (APY)
- **apy_in_initial** (string, optional): Fees earned on inbound routed payments / our start balance for the length of time this channel has been open amortized to a year (APY)
- **apy_total_initial** (string, optional): Total fees earned on routed payments / our start balance for the length of time this channel has been open amortized to a year (APY)
- **apy_lease** (string, optional): Lease fees earned over total amount leased for the lease term, amortized to a year (APY). Only appears if channel was leased out by us

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

niftynei <niftynei@gmail.com> is mainly responsible.

SEE ALSO
--------

lightning-bkpr-listincome(7), lightning-bkpr-listfunds(7),
lightning-bkpr-listaccountevents(7),
lightning-bkpr-dumpincomecsv(7), lightning-listpeers(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:435fd03765ef0a8bcaef7f309673cdac9cb7c8ba776ac77de21aea8d702998a3)
