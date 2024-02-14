lightning-bkpr-channelsapy -- Command to list stats on channel earnings
=======================================================================

SYNOPSIS
--------

**bkpr-channelsapy** [*start\_time*] [*end\_time*] 

DESCRIPTION
-----------

The **bkpr-channelsapy** RPC command lists stats on routing income, leasing income, and various calculated APYs for channel routed funds.

- **start\_time** (u64, optional): UNIX timestamp (in seconds) to filter events after the provided timestamp. The default is zero.
- **end\_time** (u64, optional): UNIX timestamp (in seconds) to filter events up to and at the provided timestamp. The default is max-int.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:bkpr-channelsapy#1",
  "method": "bkpr-channelsapy",
  "params": "{}"
}
```

RETURN VALUE
------------

On success, an object containing **channels\_apy** is returned. It is an array of objects, where each object contains:

- **account** (string): The account name. If the account is a channel, the channel\_id. The 'net' entry is the rollup of all channel accounts.
- **routed\_out\_msat** (msat): Sats routed (outbound).
- **routed\_in\_msat** (msat): Sats routed (inbound).
- **lease\_fee\_paid\_msat** (msat): Sats paid for leasing inbound (liquidity ads).
- **lease\_fee\_earned\_msat** (msat): Sats earned for leasing outbound (liquidity ads).
- **pushed\_out\_msat** (msat): Sats pushed to peer at open.
- **pushed\_in\_msat** (msat): Sats pushed in from peer at open.
- **our\_start\_balance\_msat** (msat): Starting balance in channel at funding. Note that if our start balance is zero, any \_initial field will be omitted (can't divide by zero).
- **channel\_start\_balance\_msat** (msat): Total starting balance at funding.
- **fees\_out\_msat** (msat): Fees earned on routed outbound.
- **utilization\_out** (string): Sats routed outbound / total start balance.
- **utilization\_in** (string): Sats routed inbound / total start balance.
- **apy\_out** (string): Fees earned on outbound routed payments / total start balance for the length of time this channel has been open amortized to a year (APY).
- **apy\_in** (string): Fees earned on inbound routed payments / total start balance for the length of time this channel has been open amortized to a year (APY).
- **apy\_total** (string): Total fees earned on routed payments / total start balance for the length of time this channel has been open amortized to a year (APY).
- **fees\_in\_msat** (msat, optional): Fees earned on routed inbound.
- **utilization\_out\_initial** (string, optional): Sats routed outbound / our start balance.
- **utilization\_in\_initial** (string, optional): Sats routed inbound / our start balance.
- **apy\_out\_initial** (string, optional): Fees earned on outbound routed payments / our start balance for the length of time this channel has been open amortized to a year (APY).
- **apy\_in\_initial** (string, optional): Fees earned on inbound routed payments / our start balance for the length of time this channel has been open amortized to a year (APY).
- **apy\_total\_initial** (string, optional): Total fees earned on routed payments / our start balance for the length of time this channel has been open amortized to a year (APY).
- **apy\_lease** (string, optional): Lease fees earned over total amount leased for the lease term, amortized to a year (APY). Only appears if channel was leased out by us.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "channels_apy": [
    {
      "account": "e41b2ec83e9139a9fd8f1d89b01e5d7df73099494e6b91504c39445e37485b0d",
      "routed_out_msat": 1431440,
      "routed_in_msat": 0,
      "lease_fee_paid_msat": 0,
      "lease_fee_earned_msat": 0,
      "pushed_out_msat": 0,
      "pushed_in_msat": 0,
      "our_start_balance_msat": 1000000000,
      "channel_start_balance_msat": 1000000000,
      "fees_out_msat": 0,
      "fees_in_msat": 0,
      "utilization_out": "0.1431%",
      "utilization_out_initial": "0.1431%",
      "utilization_in": "0.0000%",
      "apy_out": "0.0000%",
      "apy_out_initial": "0.0000%",
      "apy_in": "0.0000%",
      "apy_total": "0.0000%",
      "apy_total_initial": "0.0000%"
    },
    {
      "account": "net",
      "routed_out_msat": 1431440,
      "routed_in_msat": 0,
      "lease_fee_paid_msat": 0,
      "lease_fee_earned_msat": 0,
      "pushed_out_msat": 0,
      "pushed_in_msat": 0,
      "our_start_balance_msat": 1000000000,
      "channel_start_balance_msat": 1000000000,
      "fees_out_msat": 0,
      "fees_in_msat": 0,
      "utilization_out": "0.1431%",
      "utilization_out_initial": "0.1431%",
      "utilization_in": "0.0000%",
      "apy_out": "0.0000%",
      "apy_out_initial": "0.0000%",
      "apy_in": "0.0000%",
      "apy_total": "0.0000%",
      "apy_total_initial": "0.0000%"
    }
  ]
}
```

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-bkpr-listincome(7), lightning-bkpr-listfunds(7), lightning-bkpr-listaccountevents(7), lightning-bkpr-dumpincomecsv(7), lightning-listpeers(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
