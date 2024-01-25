lightning-multifundchannel -- Command for establishing many lightning channels
==============================================================================

SYNOPSIS
--------

**multifundchannel** *destinations* [*feerate*] [*minconf*] [*utxos*] [*minchannels*] [*commitment\_feerate*]

DESCRIPTION
-----------

The **multifundchannel** RPC command opens multiple payment channels
with nodes by committing a single funding transaction to the blockchain
that is shared by all channels.

If not already connected, **multifundchannel** will automatically attempt
to connect; you may provide a *@host:port* hint appended to the node ID
so that Core Lightning can learn how to connect to the node;
see lightning-connect(7).

Once the transaction is confirmed, normal channel operations may begin.
Readiness is indicated by **listpeers** reporting a *state* of
`CHANNELD_NORMAL` for the channel.

*destinations* is an array of objects, with the fields:

* *id* is the node ID, with an optional *@host:port* appended to it
  in a manner understood by **connect**; see lightning-connect(7).
  Each entry in the *destinations* array must have a unique node *id*.
* *amount* is the amount in satoshis taken from the internal wallet
  to fund the channel (but if we have any anchor channels, this will always leave at least `min-emergency-msat` as change).
  The string *all* can be used to specify all available funds
  (or 16,777,215 satoshi if more is available and large channels were
  not negotiated with the peer).
  Otherwise it is in satoshi precision; it can be
   a whole number,
   a whole number ending in *sat*,
   a whole number ending in *000msat*, or
   a number with 1 to 8 decimal places ending in *btc*.
  The value cannot be less than the dust limit, currently 546 satoshi
  as of this writing, nor more than 16,777,215 satoshi
  (unless large channels were negotiated with the peer).
* *announce* is an optional flag that indicates whether to announce
  the channel with this, default `true`.
  If set to `false`, the channel is unpublished.
* *push\_msat* is the amount of millisatoshis to outright give to the
  node.
  This is a gift to the peer, and you do not get a proof-of-payment
  out of this.
* *close\_to* is a Bitcoin address to which the channel funds should be sent to
  on close. Only valid if both peers have negotiated
  `option_upfront_shutdown_script`.  Returns `close_to` set to
  closing script iff is negotiated.
* *request\_amt* is the amount of liquidity you'd like to lease from peer.
  If peer supports `option_will_fund`, indicates to them to include this
  much liquidity into the channel. Must also pass in *compact\_lease*.
* *compact\_lease* is a compact represenation of the peer's expected
  channel lease terms. If the peer's terms don't match this set, we will
  fail to open the channel to this destination.
* *reserve* is the amount we want the peer to maintain on its side of the
  channel. Default is 1% of the funding amount. It can be a whole number, a
  whole number ending in *sat*, a whole number ending in *000msat*, or a number
  with 1 to 8 decimal places ending in *btc*.

There must be at least one entry in *destinations*;
it cannot be an empty array.

*feerate* is an optional feerate used for the opening transaction, and
if *commitment\_feerate* is not set, as initial feerate for commitment
and HTLC transactions.  See NOTES in lightning-feerates(7) for possible
values.  The default is *normal*.

*minconf* specifies the minimum number of confirmations that used
outputs should have. Default is 1.

*utxos* specifies the utxos to be used to fund the channel, as an array
of "txid:vout".

*minchannels*, if specified, will re-attempt funding as long as at least
this many peers remain (must not be zero).
The **multifundchannel** command will only fail if too many peers fail
the funding process.

*commitment\_feerate* is the initial feerate for commitment and HTLC
transactions. See *feerate* for valid values.

RETURN VALUE
------------

This command opens multiple channels with a single large transaction,
thus only one transaction is returned.

If *minchannels* was specified and is less than the number of destinations,
then it is possible that one or more of the destinations
do not have a channel even if **multifundchannel** succeeded.

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **tx** (hex): The raw transaction which funded the channel
- **txid** (txid): The txid of the transaction which funded the channel
- **channel\_ids** (array of objects):
  - **id** (pubkey): The peer we opened the channel with
  - **outnum** (u32): The 0-based output index showing which output funded the channel
  - **channel\_id** (hex): The channel\_id of the resulting channel (always 64 characters)
  - **close\_to** (hex, optional): The raw scriptPubkey which mutual close will go to; only present if *close\_to* parameter was specified and peer supports `option_upfront_shutdown_script`
- **failed** (array of objects, optional): any peers we failed to open with (if *minchannels* was specified less than the number of destinations):
  - **id** (pubkey): The peer we failed to open the channel with
  - **method** (string): What stage we failed at (one of "connect", "openchannel\_init", "fundchannel\_start", "fundchannel\_complete")
  - **error** (object):
    - **code** (integer): JSON error code from failing stage
    - **message** (string): Message from stage
    - **data**: Additional error data

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, none of the channels are created.

The following error codes may occur:

* -1: Catchall nonspecific error.
- 300: The maximum allowed funding amount is exceeded.
- 301: There are not enough funds in the internal wallet (including fees) to create the transaction.
- 302: The output amount is too small, and would be considered dust.
- 303: Broadcasting of the funding transaction failed, the internal call to bitcoin-cli returned with an error.
- 313: The `min-emergency-msat` reserve not be preserved (and we have or are opening anchor channels).

Failure may also occur if **lightningd** and the peer cannot agree on
channel parameters (funding limits, channel reserves, fees, etc.).
See lightning-fundchannel\_start(7) and lightning-fundchannel\_complete(7).

There may be rare edge cases where a communications failure later in
the channel funding process will cancel the funding locally, but
the peer thinks the channel is already waiting for funding lockin.
In that case, the next time we connect to the peer, our node will
tell the peer to forget the channel, but some nodes (in particular,
Core Lightning nodes) will disconnect when our node tells them to
forget the channel.
If you immediately **multifundchannel** with that peer, it could
trigger this connect-forget-disconnect behavior, causing the
second **multifundchannel** to fail as well due to disconnection.
Doing a **connect** with the peers separately, and waiting for a
few seconds, should help clear this hurdle;
running **multifundchannel** a third time would also clear this.

EXAMPLE
-------

This example opens three channels at once, with amounts 200,000 sats, 3,000,000 sats and the final channel using all remaining funds (actually, capped at 16,777,215 sats because large-channels is not enabled):

```
$ lightning-cli multifundchannel '[{"id":"0201f42e167959c74d396ac57652fcea63c63940f78e8239cce5720df4d85ef857@127.0.0.1:7272", "amount":"200000sat"}, {"id":"0304a2468065535f9459567686e0f02b40f06e341d3eb2a62ec6763bcf2ccfd207@127.0.0.1:7373", "amount":"0.03btc"}, {"id":"0391f4c475050bb15871da5a72b1f3a1798de3d2e5fb4ffa262899b8d8e1f0b764@127.0.0.1:7474", "amount":"all"}]'
{
   "tx": "02000000000101fbe3c68db87b72f82c3f5447b0bc032469c78e71f229ac99c230807ff378a9d80000000000fdffffff04400d0300000000002200202e9897ed5f9b237aa27fd5d02d24157cd452b0d3f0a5bb03d38ff73f9f8f384bffffff0000000000220020439d797ada249e1e12f8d27cabb7330de3c8de0456fb54892deb7b9c72b0ff7c1dc9b50400000000225120046e3966a2d5e43c1f1e0676161905782e1e7c00811485c618f5144f328f4e2bc0c62d0000000000220020e36fd5c03c3586c3763d8b4c9d8650f396ff1c8a460137fb09b60ee82536a3b20140ea4d564e91c919b50a2d32886f1d414de773491119beb1364b92f15d6d03e1810e5ddea89c265e42f2e96bb028dfb3aa0b5b30072ddcc78daad727503c53e37fa9010000",
   "txid": "90dc53922b70628fc9e7804ad0b8cd0fb41f050d94ffa2db3b16e918c96c022a",
   "channel_ids": [
      {
         "id": "0201f42e167959c74d396ac57652fcea63c63940f78e8239cce5720df4d85ef857",
         "channel_id": "25c8253e66a860d17916cc0c21386e310eba9900030a68ec6ff6f59a8401a872",
         "outnum": 0
      },
      {
         "id": "0304a2468065535f9459567686e0f02b40f06e341d3eb2a62ec6763bcf2ccfd207",
         "channel_id": "51749d724892a406896f6bf2e2f8c0b03399d0436691f294839897fa167e6521",
         "outnum": 3
      },
      {
         "id": "0391f4c475050bb15871da5a72b1f3a1798de3d2e5fb4ffa262899b8d8e1f0b764",
         "channel_id": "7e1414e72c081f0754fa18c1657cedabe696aa9ffeaf0b936bfbe3a28f2829d1",
         "outnum": 1
      }
   ],
   "failed": []
}
```

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-listfunds(), lightning-listpeers(7),
lightning-fundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:86f5966b49a03858655163407e15b4331147d52dd6e773480157279a222e77a2)
