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

The *psbt* must have all signatures attached to all inputs that you have added
to it or it will fail.

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

[comment]: # (GENERATE-FROM-SCHEMA-END)

SEE ALSO
--------

lightning-splice_init(7), lightning-splice_update(7)

AUTHOR
------

Dusty <<@dusty_daemon>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:429eb13039cd6af7180c7de1d74f001eb1090c6c6d404bac0dcb2af51e0ab0f4)
