lightning-listchannels -- Command to query active lightning channels in the entire network
==========================================================================================

SYNOPSIS
--------

**listchannels** [*short\_channel\_id*] [*source*] [*destination*] 

DESCRIPTION
-----------

The **listchannels** RPC command returns data on channels that are known to the node. Because channels may be bidirectional, up to 2 objects will be returned for each channel (one for each direction).

Only one of *short\_channel\_id*, *source* or *destination* can be supplied. If nothing is supplied, data on all lightning channels known to this node, are returned. These can be local channels or public channels broadcast on the gossip network.

- **short\_channel\_id** (short\_channel\_id, optional): If short\_channel\_id is a short channel id, then only known channels with a matching short\_channel\_id are returned. Otherwise, it must be null.
- **source** (pubkey, optional): If source is a node id, then only channels leading from that node id are returned.
- **destination** (pubkey, optional): If destination is a node id, then only channels leading to that node id are returned.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listchannels#1",
  "method": "listchannels",
  "params": {
    "short_channel_id": "103x1x0",
    "source": null,
    "destination": null
  }
}
{
  "id": "example:listchannels#2",
  "method": "listchannels",
  "params": {
    "short_channel_id": null,
    "source": null,
    "destination": null
  }
}
```

RETURN VALUE
------------

On success, an object containing **channels** is returned. It is an array of objects, where each object contains:

- **source** (pubkey): The source node.
- **destination** (pubkey): The destination node.
- **short\_channel\_id** (short\_channel\_id): Short channel id of channel.
- **direction** (u32): Direction (0 if source < destination, 1 otherwise).
- **public** (boolean): True if this is announced (from *v24.02*, being false is deprecated).
- **amount\_msat** (msat): The total capacity of this channel (always a whole number of satoshis).
- **message\_flags** (u8): As defined by BOLT #7.
- **channel\_flags** (u8): As defined by BOLT #7.
- **active** (boolean): True unless source has disabled it (or (deprecated in *v24.02*) it's a local channel and the peer is disconnected or it's still opening or closing).
- **last\_update** (u32): UNIX timestamp on the last channel\_update from *source*.
- **base\_fee\_millisatoshi** (u32): Base fee changed by *source* to use this channel.
- **fee\_per\_millionth** (u32): Proportional fee changed by *source* to use this channel, in parts-per-million.
- **delay** (u32): The number of blocks delay required by *source* to use this channel.
- **htlc\_minimum\_msat** (msat): The smallest payment *source* will allow via this channel.
- **features** (hex): BOLT #9 features bitmap for this channel.
- **htlc\_maximum\_msat** (msat, optional): The largest payment *source* will allow via this channel.

If one of *short\_channel\_id*, *source* or *destination* is supplied and no matching channels are found, a 'channels' object with an empty list is returned.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "channels": []
}
{
  "channels": [
    {
      "source": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "destination": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
      "short_channel_id": "103x1x0",
      "direction": 0,
      "public": true,
      "amount_msat": 1000000000,
      "message_flags": 1,
      "channel_flags": 0,
      "active": true,
      "last_update": 1706153393,
      "base_fee_millisatoshi": 1,
      "fee_per_millionth": 10,
      "delay": 6,
      "htlc_minimum_msat": 0,
      "htlc_maximum_msat": 990000000,
      "features": ""
    },
    {
      "source": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
      "destination": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
      "short_channel_id": "103x1x0",
      "direction": 1,
      "public": true,
      "amount_msat": 1000000000,
      "message_flags": 1,
      "channel_flags": 1,
      "active": true,
      "last_update": 1706153393,
      "base_fee_millisatoshi": 1,
      "fee_per_millionth": 10,
      "delay": 6,
      "htlc_minimum_msat": 0,
      "htlc_maximum_msat": 990000000,
      "features": ""
    }
  ]
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.

AUTHOR
------

Michael Hawkins <<michael.hawkins@protonmail.com>>.

SEE ALSO
--------

lightning-fundchannel(7), lightning-listnodes(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

BOLT #7: <https://github.com/lightning/bolts/blob/master/07-routing-gossip.md>
