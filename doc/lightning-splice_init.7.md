lightning-splice\_init -- Command to initiate a channel to a peer
=====================================================================

SYNOPSIS
--------
**(WARNING: experimental-splicing only)**

**splice\_init** *channel\_id* *relative\_amount* [*initalpsbt*] [*feerate\_per\_kw*] [*force\_feerate*]

DESCRIPTION
-----------

`splice_init` is a low level RPC command which initiates a channel splice for a
given channel specified by `channel_id`.

*channel\_id* is the channel id of the channel to be spliced.

*relative\_amount* is a positive or negative amount of satoshis to add or
subtract from the channel.

*initalpsbt* is the (optional) base 64 encoded PSBT to begin with. If not
specified, one will be generated automatically.

*feerate\_per\_kw* is the miner fee we promise our peer to pay for our side of
the splice transaction. It is calculated by `feerate_per_kw` *
our\_bytes\_in\_splice\_tx / 1000.

*force\_feerate* is a boolean flag. By default splices will fail if the fee
provided looks too high. This is to protect against accidentally setting your
fee higher than intended. Set `force_feerate` to true to skip this saftey check.

Here is an example set of splice commands that will splice in 100,000 sats to
the first channel that comes out of `listpeerchannels`. The example assumes
you already have at least one confirmed channel.
```shell
RESULT=$(lightning-cli listpeerchannels)
CHANNEL_ID=$(echo $RESULT| jq -r ".channels[0].channel_id")
echo $RESULT

RESULT=$(lightning-cli fundpsbt -k satoshi=100000sat feerate=urgent startweight=800 excess_as_change=true)
INITIALPSBT=$(echo $RESULT | jq -r ".psbt")
echo $RESULT

RESULT=$(lightning-cli splice_init $CHANNEL_ID 100000 $INITIALPSBT)
PSBT=$(echo $RESULT | jq -r ".psbt")
echo $RESULT

RESULT=$(lightning-cli splice_update $CHANNEL_ID $PSBT)
PSBT=$(echo $RESULT | jq -r ".psbt")
echo $RESULT

RESULT=$(lightning-cli signpsbt $PSBT)
PSBT=$(echo $RESULT | jq -r ".signed_psbt")
echo $RESULT

lightning-cli splice_signed $CHANNEL_ID $PSBT
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **psbt** (string): the (incomplete) PSBT of the splice transaction

[comment]: # (GENERATE-FROM-SCHEMA-END)

SEE ALSO
--------

AUTHOR
------

@dusty\_daemon

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:40121e2e7b0db8c99de12b4fd086f58f63e0d6643b9da1c1697a34dd5057454e)
