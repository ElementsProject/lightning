lightning-splice\_update -- Command to initiate a channel to a peer
=====================================================================

SYNOPSIS
--------
**(WARNING: experimental-splicing only)**

**splice\_update** *channel\_id* *psbt*

DESCRIPTION
-----------

`splice_update` is a low level RPC command which updates the active channel
splice associated with `channel_id`.

*channel\_id* is the channel id of the channel being spliced.

*psbt* is the base 64 encoded PSBT returned from `splice_init` with any changes
added by the user.

`splice_update` must be called repeatidly until the result `commitments_secured`
is `true`. Each time `splice_update` is called, it will return a new PSBT that
may have changes. In the simplest case, you take the returned `psbt` and pass
it back into `splice_update` for the incoming `psbt` field.

For more complex use cases, you may modify the `psbt` both before calling
`splice_update` and inbetween subsequent calls until  `commitments_secured` is
`true`. After which point you can no long make modifications to the PSBT (beyond
signing, which comes later with `splice_signed`).

Each `splice_update` result may include changes to the PSBT specified by your
channel peer. You can review these changes between calls to `splice_update` to
perform additional validation or strategy adjustment.

Typically, `splice_update` will return `commitments_secured` true after one call
but you should assume it will need multiple calls. Here is an example way to
call `splice_update`

```shell
RESULT="{\"commitments_secured\":false}"
while [[ $(echo $RESULT | jq -r ".commitments_secured") == "false" ]]
do
	RESULT=$(lightning-cli splice_update $CHANNEL_ID $PSBT)
	PSBT=$(echo $RESULT | jq -r ".psbt")
	echo $RESULT
done
```

Before each call to `splice_update` you have the opportunity
to make additional changes.

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

- **psbt** (string): the (incomplete) PSBT of the splice transaction
- **commitments\_secured** (boolean): whether or not the commitments were secured

[comment]: # (GENERATE-FROM-SCHEMA-END)

SEE ALSO
--------

AUTHOR
------

@dusty\_daemon

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:e7f65170f8d32eb56b327a4eae0b5978517aba8e4f12e8271e71481afc33e0f3)
