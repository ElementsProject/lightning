lightning-splice\_signed -- Command to initiate a channel to a peer
=====================================================================

SYNOPSIS
--------
**(WARNING: experimental-splicing only)**

**splice\_signed** *channel\_id* *psbt* [*sign\_first*]

DESCRIPTION
-----------

`splice_signed` is a low level RPC command which finishes the active channel
splice associated with `channel_id`.

*psbt* is the final version of the psbt to complete the splice with.

*channel\_id* is optionally the channel id of the channel being spliced.

*sign\_first* is a flag that makes our node offer the final splice signature
first (defaults to false). When false, the node will calculate who should
sign first based off who is adding inputting the least sats to the splice as per
spec.

The *psbt* must have all signatures attached to all inputs that you have added
to it or it will fail.

If *channel\_id* is not specified, the psbt will be scanned for channel\_ids.

In this example we funded the psbt from our lightning node, so we can use the
lightning node to sign for its funds.

```shell
RESULT=$(lightning-cli signpsbt $PSBT)
PSBT=$(echo $RESULT | jq -r ".signed_psbt")
echo $RESULT

lightning-cli splice_signed $CHANNEL_ID $PSBT
```

Here is a full example set of splice commands that will splice in 100,000 sats
to the first channel that comes out of `listpeerchannels`. The example assumes
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

RESULT="{\"commitments_secured\":false}"
while [[ $(echo $RESULT | jq -r ".commitments_secured") == "false" ]]
do
	RESULT=$(lightning-cli splice_update $CHANNEL_ID $PSBT)
	PSBT=$(echo $RESULT | jq -r ".psbt")
	echo $RESULT
done

RESULT=$(lightning-cli signpsbt -k psbt="$PSBT")
PSBT=$(echo $RESULT | jq -r ".signed_psbt")
echo $RESULT

lightning-cli splice_signed $CHANNEL_ID $PSBT
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **tx** (hex): The hex representation of the final transaction that is published
- **txid** (txid): The txid is of the final transaction
- **psbt** (string, optional): The psbt of the final transaction *(added v24.02)*

[comment]: # (GENERATE-FROM-SCHEMA-END)

SEE ALSO
--------

AUTHOR
------

@dusty\_daemon

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:a094d4147d83dc50a92e2287b206b7f54bb9ed089bd54a595a3e75141f4f0b61)
