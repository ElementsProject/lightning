lightning-setchannel -- Command for configuring fees / htlc range advertized for a channel
==========================================================================================

SYNOPSIS
--------

**setchannel** *id* [*feebase*] [*feeppm*] [*htlcmin*] [*htlcmax*] [*enforcedelay*] [*ignorefeelimits*] 

DESCRIPTION
-----------

The **setchannel** RPC command sets channel specific routing fees, and `htlc_minimum_msat` or `htlc_maximum_msat` as defined in BOLT #7. The channel has to be in normal or awaiting state. This can be checked by **listpeers** reporting a *state* of CHANNELD\_NORMAL or CHANNELD\_AWAITING\_LOCKIN for the channel.

These changes (for a public channel) will be broadcast to the rest of the network (though many nodes limit the rate of such changes they will accept: we allow 2 a day, with a few extra occasionally).

- **id** (string): Should contain a scid (short channel ID), channel id or peerid (pubkey) of the channel to be modified. If *id* is set to `all`, the updates are applied to all channels in states CHANNELD\_NORMAL CHANNELD\_AWAITING\_LOCKIN or DUALOPEND\_AWAITING\_LOCKIN. If *id* is a peerid, all channels with the +peer in those states are changed.
- **feebase** (msat, optional): Value in millisatoshi that is added as base fee to any routed payment: if omitted, it is unchanged. It can be a whole number, or a whole number ending in *msat* or *sat*, or a number with three decimal places ending in *sat*, or a number with 1 to 11 decimal places ending in *btc*.
- **feeppm** (u32, optional): Value that is added proportionally per-millionths to any routed payment volume in satoshi. For example, if ppm is 1,000 and 1,000,000 satoshi is being routed through the channel, an proportional fee of 1,000 satoshi is added, resulting in a 0.1% fee.
- **htlcmin** (msat, optional): Value that limits how small an HTLC we will forward: if omitted, it is unchanged. It can be a whole number, or a whole number ending in *msat* or *sat*, or a number with three decimal places ending in *sat*, or a number with 1 to 11 decimal places ending in *btc*. Note that the peer also enforces a minimum for the channel: setting it below that will simply set it to that value with a warning. Also note that *htlcmin* only applies to forwarded HTLCs: we can still send smaller payments ourselves. The default is no lower limit.
- **htlcmax** (msat, optional): Value that limits how large an HTLC we will forward: if omitted, it is unchanged. It can be a whole number, or a whole number ending in *msat* or *sat*, or a number with three decimal places ending in *sat*, or a number with 1 to 11 decimal places ending in *btc*. Note that *htlcmax* only applies to forwarded HTLCs: we can still send larger payments ourselves. The default is no effective limit.
- **enforcedelay** (u32, optional): Number of seconds to delay before enforcing the new fees/htlc max. This gives the network a chance to catch up with the new rates and avoids rejecting HTLCs before they do. This only has an effect if rates are increased (we always allow users to overpay fees) or *htlcmax* is decreased, and only applied to a single rate increase per channel (we don't remember an arbitrary number of prior feerates) and if the node is restarted the updated configuration is enforced immediately. The default is 600, which is ten minutes.
- **ignorefeelimits** (boolean, optional): If set to True means to allow the peer to set the commitment transaction fees (or closing transaction fees) to any value they want. This is dangerous: they could set an exorbitant fee (so HTLCs are unenforcable), or a tiny fee (so that commitment transactions cannot be relayed), but avoids channel breakage in case of feerate disagreements. (Note: the global `ignore_fee_limits` setting overrides this). *(added v23.08)*

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:setchannel#1",
  "method": "setchannel",
  "params": {
    "id": "103x1x0",
    "feebase": null,
    "feeppm": null,
    "htlcmin": null,
    "htlcmax": null,
    "enforcedelay": null,
    "ignorefeelimits": true
  }
}
{
  "id": "example:setchannel#2",
  "method": "setchannel",
  "params": {
    "id": "0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199",
    "feebase": 4000,
    "feeppm": 300,
    "htlcmin": null,
    "htlcmax": null,
    "enforcedelay": 0,
    "ignorefeelimits": null
  }
}
```

RETURN VALUE
------------

On success, an object containing **channels** is returned. It is an array of objects, where each object contains:

- **peer\_id** (pubkey): The node\_id of the peer.
- **channel\_id** (hash): The channel\_id of the channel.
- **fee\_base\_msat** (msat): The resulting feebase (this is the BOLT #7 name).
- **fee\_proportional\_millionths** (u32): The resulting feeppm (this is the BOLT #7 name).
- **ignore\_fee\_limits** (boolean): If we are now allowing peer to set feerate on commitment transaction without restriction. *(added v23.08)*
- **minimum\_htlc\_out\_msat** (msat): The resulting htlcmin we will advertize (the BOLT #7 name is htlc\_minimum\_msat).
- **maximum\_htlc\_out\_msat** (msat): The resulting htlcmax we will advertize (the BOLT #7 name is htlc\_maximum\_msat).
- **short\_channel\_id** (short\_channel\_id, optional): The short\_channel\_id (if locked in).
- the following warnings are possible:
  - **warning\_htlcmin\_too\_low**: The requested htlcmin was too low for this peer, so we set it to the minimum they will allow.
  - **warning\_htlcmax\_too\_high**: The requested htlcmax was greater than the channel capacity, so we set it to the channel capacity.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "channels": [
    {
      "peer_id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
      "channel_id": "90210d39d12a65d239ece267c5f48e0a82e7cb95724e658f6d99f370064faad1",
      "short_channel_id": "103x1x0",
      "fee_base_msat": 1,
      "fee_proportional_millionths": 10,
      "minimum_htlc_out_msat": 0,
      "maximum_htlc_out_msat": 990000000,
      "ignore_fee_limits": true
    }
  ]
}
{
  "channels": [
    {
      "peer_id": "0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199",
      "channel_id": "9c54c71bbbe59591cc3162e14fc4ff58c146f085c07d0f206ea679a8231d03ab",
      "short_channel_id": "103x3x0",
      "fee_base_msat": 4000,
      "fee_proportional_millionths": 300,
      "minimum_htlc_out_msat": 0,
      "maximum_htlc_out_msat": 990000000,
      "ignore_fee_limits": false
    }
  ]
}
```

ERRORS
------

The following error codes may occur:

- -1: Channel is in incorrect state, i.e. Catchall nonspecific error.
- -32602: JSONRPC2\_INVALID\_PARAMS, i.e. Given id is not a channel ID or short channel ID.

AUTHOR
------

Michael Schmoock <<michael@schmoock.net>> is the author of this feature.

SEE ALSO
--------

lightningd-config(5), lightning-fundchannel(7), lightning-listchannels(7), lightning-listpeers(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
