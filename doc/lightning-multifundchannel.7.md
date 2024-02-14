lightning-multifundchannel -- Command for establishing many lightning channels
==============================================================================

SYNOPSIS
--------

**multifundchannel** *destinations* [*feerate*] [*minconf*] [*utxos*] [*minchannels*] [*commitment\_feerate*] 

DESCRIPTION
-----------

The **multifundchannel** RPC command opens multiple payment channels with nodes by committing a single funding transaction to the blockchain that is shared by all channels.

If not already connected, **multifundchannel** will automatically attempt to connect; you may provide a *@host:port* hint appended to the node ID so that Core Lightning can learn how to connect to the node; see lightning-connect(7).

Once the transaction is confirmed, normal channel operations may begin. Readiness is indicated by **listpeers** reporting a *state* of `CHANNELD_NORMAL` for the channel.

- **destinations** (array of objects): There must be at least one entry in *destinations*; it cannot be an empty array.:
  - **id** (string): Node ID, with an optional *@host:port* appended to it in a manner understood by **connect**; see lightning-connect(7). Each entry in the *destinations* array must have a unique node *id*. If not already connected, **multifundchannel** will automatically attempt to connect to the node.
  - **amount** (msat): Amount in satoshis taken from the internal wallet to fund the channel (but if we have any anchor channels, this will always leave at least `min-emergency-msat` as change). The string *all* can be used to specify all available funds (or 16,777,215 satoshi if more is available and large channels were not negotiated with the peer). Otherwise it is in satoshi precision; it can be a whole number, a whole number ending in *sat*, a whole number ending in *000msat*, or a number with 1 to 8 decimal places ending in *btc*. The value cannot be less than the dust limit, currently 546 satoshi as of this writing, nor more than 16,777,215 satoshi (unless large channels were negotiated with the peer).
  - **announce** (boolean, optional): Flag that indicates whether to announce the channel with this. If set to `False`, the channel is unpublished. The default is `True`.
  - **push\_msat** (msat, optional): Amount of millisatoshis to outright give to the node. This is a gift to the peer, and you do not get a proof-of-payment out of this.
  - **close\_to** (string, optional): Bitcoin address to which the channel funds should be sent to on close. Only valid if both peers have negotiated `option_upfront_shutdown_script` Returns `close_to` set to closing script iff is negotiated.
  - **request\_amt** (msat, optional): Amount of liquidity you'd like to lease from peer. If peer supports `option_will_fund`, indicates to them to include this much liquidity into the channel. Must also pass in *compact\_lease*.
  - **compact\_lease** (string, optional): Compact representation of the peer's expected channel lease terms. If the peer's terms don't match this set, we will fail to open the channel to this destination.
  - **mindepth** (u32, optional): Number of confirmations before we consider the channel active.
  - **reserve** (msat, optional): Amount we want the peer to maintain on its side of the channel. It can be a whole number, a whole number ending in *sat*, a whole number ending in *000msat*, or a number with 1 to 8 decimal places ending in *btc*. The default is 1% of the funding amount.
- **feerate** (feerate, optional): Feerate used for the opening transaction, and if *commitment\_feerate* is not set, as initial feerate for commitment and HTLC transactions. See NOTES in lightning-feerates(7) for possible values. The default is *normal*.
- **minconf** (integer, optional): Minimum number of confirmations that used outputs should have. The default is 1.
- **utxos** (array of outpoints, optional):
  - (outpoint, optional): Utxos to be used to fund the channel, as an array of `txid:vout`.
- **minchannels** (integer, optional): Re-attempt funding as long as at least this many peers remain (must not be zero). The **multifundchannel** command will only fail if too many peers fail the funding process.
- **commitment\_feerate** (feerate, optional): Initial feerate for commitment and HTLC transactions. See *feerate* for valid values.

EXAMPLE USAGE
-------------

This example opens three channels at once, with amounts 200,000 sats, 3,000,000 sats and the final channel using all remaining funds (actually, capped at 16,777,215 sats because large-channels is not enabled):

```shell
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

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:multifundchannel#1",
  "method": "multifundchannel",
  "params": {
    "destinations": [
      {
        "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59@localhost:41939",
        "amount": 50000
      }
    ],
    "feerate": "10000perkw",
    "minconf": null,
    "utxos": null,
    "minchannels": null,
    "commitment_feerate": "2000perkw"
  }
}
{
  "id": "example:multifundchannel#2",
  "method": "multifundchannel",
  "params": {
    "destinations": [
      {
        "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59@localhost:44663",
        "amount": 50000
      },
      {
        "id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d@localhost:34631",
        "amount": 50000
      },
      {
        "id": "0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199@localhost:34617",
        "amount": 50000
      }
    ],
    "feerate": null,
    "minconf": null,
    "utxos": null,
    "minchannels": 1
  }
}
```

RETURN VALUE
------------

This command opens multiple channels with a single large transaction, thus only one transaction is returned.

If *minchannels* was specified and is less than the number of destinations, then it is possible that one or more of the destinations do not have a channel even if **multifundchannel** succeeded.
On success, an object is returned, containing:

- **tx** (hex): The raw transaction which funded the channel.
- **txid** (txid): The txid of the transaction which funded the channel.
- **channel\_ids** (array of objects):
  - **id** (pubkey): The peer we opened the channel with.
  - **outnum** (u32): The 0-based output index showing which output funded the channel.
  - **channel\_id** (hash): The channel\_id of the resulting channel.
  - **channel\_type** (object): Channel\_type as negotiated with peer. *(added v24.02)*:
    - **bits** (array of u32s): Each bit set in this channel\_type. *(added v24.02)*:
      - (u32, optional): Bit number.
    - **names** (array of strings): Feature name for each bit set in this channel\_type. *(added v24.02)*:
      - (string, optional) (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even"): Name of feature bit.
  - **close\_to** (hex, optional): The raw scriptPubkey which mutual close will go to; only present if *close\_to* parameter was specified and peer supports `option_upfront_shutdown_script`.
- **failed** (array of objects, optional): Any peers we failed to open with (if *minchannels* was specified less than the number of destinations).:
  - **id** (pubkey): The peer we failed to open the channel with.
  - **method** (string) (one of "connect", "openchannel\_init", "fundchannel\_start", "fundchannel\_complete"): What stage we failed at.
  - **error** (object):
    - **code** (integer): JSON error code from failing stage.
    - **message** (string): Message from stage.
    - **data**: Additional error data.

On failure, none of the channels are created.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "tx": "0200000000010100a8ceb6f76c49c8c0c809ca359461540708a9a5ac56e56e6a7aaafb35f4d3850000000000fdffffff0250c30000000000002200205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cd0623ff030000000022512063ffee4ea7d51e6cadf9086e286a2527922aaa25b8c53aebf32fa32a0a627f5a02473044022064763837f2cc84507eb1fc28c9e95d51174e1da4b8755da8e67fe21e37d0a8b402206295d0f19625f014819361a20572b936d81f6c5ba419e56997e882f3a7be094a012103d745445c9362665f22e0d96e9e766f273f3260dea39c8a76bfa05dd2684ddccf66000000",
  "txid": "ecba36e93bcf40542d43a05ef550bb0e4be51d766aa2ec8c5640a0d431ab0d06",
  "channel_ids": [
    {
      "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "channel_id": "060dab31d4a040568ceca26a761de54b0ebb50f55ea0432d5440cf3be936baec",
      "channel_type": {
        "bits": [
          12
        ],
        "names": [
          "static_remotekey/even"
        ]
      },
      "outnum": 0
    }
  ],
  "failed": []
}
{
  "tx": "020000000001023041611dac05004825ab64781b4a33bf622380bf90196fae689196b1850a1f8f0000000000fdffffff5646519c565466c9588a88400ec71a39a2c0b6988beadb32491a13d9b89f85360100000000fdffffff0250c3000000000000220020181492c29a989f099fd2cf412c74b192dd095e81f4e4f6bec45bd1fbfdd2cfd983720000000000002251203e8a03f678bb7ca048baecc39788530560ea049816d604f72925e425288446c80140caa3b93c6667e4fe0026417cc87ae9dfd16d80018e7c6dcd6dfcee4d6cab7c7e84181baeb95ba25934ad1aa6b57f83c8287bf1b727123350b35549a3abe15b060140b3c6626b9b57081cc7eb5e4f518669764d265fb84316d8fb610e19ede13c5a370c1072861b909ec923acec980adb4a3e488ee3c6f9c49164bd4596945b52f62678000000",
  "txid": "1fcc6d46200443ad21e3a1a1628b862bafd0d75c0b4454f5494957097bc7930d",
  "channel_ids": [
    {
      "id": "0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199",
      "channel_id": "0d93c77b09574949f554440b5cd7d0af2b868b62a1a1e321ad430420466dcc1f",
      "channel_type": {
        "bits": [
          12,
          22
        ],
        "names": [
          "static_remotekey/even",
          "anchors_zero_fee_htlc_tx/even"
        ]
      },
      "outnum": 0
    }
  ],
  "failed": [
    {
      "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "method": "connect",
      "error": {
        "code": 401,
        "message": "All addresses failed: 127.0.0.1:44663: Connection establishment: Connection refused. "
      }
    },
    {
      "id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
      "method": "connect",
      "error": {
        "code": 401,
        "message": "All addresses failed: 127.0.0.1:34631: Connection establishment: Connection refused. "
      }
    }
  ]
}
```

ERRORS
------

The following error codes may occur:

- -1: Catchall nonspecific error.
- 300: The maximum allowed funding amount is exceeded.
- 301: There are not enough funds in the internal wallet (including fees) to create the transaction.
- 302: The output amount is too small, and would be considered dust.
- 303: Broadcasting of the funding transaction failed, the internal call to bitcoin-cli returned with an error.
- 313: The `min-emergency-msat` reserve not be preserved (and we have or are opening anchor channels).

Failure may also occur if **lightningd** and the peer cannot agree on channel parameters (funding limits, channel reserves, fees, etc.). See lightning-fundchannel\_start(7) and lightning-fundchannel\_complete(7).

There may be rare edge cases where a communications failure later in the channel funding process will cancel the funding locally, but the peer thinks the channel is already waiting for funding lockin. In that case, the next time we connect to the peer, our node will tell the peer to forget the channel, but some nodes (in particular, Core Lightning nodes) will disconnect when our node tells them to forget the channel. If you immediately **multifundchannel** with that peer, it could trigger this connect-forget-disconnect behavior, causing the second **multifundchannel** to fail as well due to disconnection. Doing a **connect** with the peers separately, and waiting for a few seconds, should help clear this hurdle; running **multifundchannel** a third time would also clear this.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-listfunds(), lightning-listpeers(7), lightning-fundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
