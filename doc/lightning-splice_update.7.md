lightning-splice\_update -- Command to initiate a channel to a peer
===================================================================

SYNOPSIS
--------

**(WARNING: experimental-splicing only)**

**splice\_update** *channel\_id* *psbt* 

DESCRIPTION
-----------

Command *added* in v23.08.

`splice_update` is a low level RPC command which updates the active channel splice associated with `channel_id`.

`splice_update` must be called repeatidly until the result `commitments_secured` is `true`. Each time `splice_update` is called, it will return a new PSBT that may have changes. In the simplest case, you take the returned `psbt` and pass it back into `splice_update` for the incoming `psbt` field.

For more complex use cases, you may modify the `psbt` both before calling `splice_update` and inbetween subsequent calls until `commitments_secured` is `true`. After which point you can no long make modifications to the PSBT (beyond signing, which comes later with `splice_signed`).

Each `splice_update` result may include changes to the PSBT specified by your channel peer. You can review these changes between calls to `splice_update` to perform additional validation or strategy adjustment.

Typically, `splice_update` will return `commitments_secured` true after one call but you should assume it will need multiple calls.

- **channel\_id** (hash): The channel id of the channel to be spliced.
- **psbt** (string): The base 64 encoded PSBT returned from `splice_init` with any changes added by the user.

EXAMPLE USAGE
-------------

Here is an example way to call `splice_update`

```shell
RESULT={"commitments_secured":false}
while [[ $(echo $RESULT | jq -r ".commitments_secured") == "false" ]]
do
  RESULT=$(lightning-cli splice_update $CHANNEL_ID $PSBT)
  PSBT=$(echo $RESULT | jq -r ".psbt")
  echo $RESULT
done
```

Before each call to `splice_update` you have the opportunity to make additional changes.

Here is a full example set of splice commands that will splice in 100,000 sats to the first channel that comes out of `listpeerchannels`. The example assumes you already have at least one confirmed channel.

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

RESULT={"commitments_secured":false}
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

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:splice_update#1",
  "method": "splice_update",
  "params": {
    "channel_id": "5677721c35a424a23d6dcc7c909036e505ae68650e09d59733b4b7e73003a4dc",
    "psbt": "cHNidP8BAgQCAAAAAQMEbAAAAAEEAQIBBQECAQYBAwH7BAIAAAAAAQD2AgAAAAABAYulMzSBYSogKOBxk3Kg+HN0Hl81kGsQVuw2mwoetN33AQAAAAD9////AkBCDwAAAAAAIgAgW4zTuRTPZ83Y+mJzyTA1PdNkdnNPvZYhAsLfU7kIgM0BLw8AAAAAACJRIGP/7k6n1R5srfkIbihqJSeSKqoluMU66/MvoyoKYn9aAkcwRAIgFlrmLyNU919XilsjNJ5sxvlE36XmUmRAoDD36K8BZ+cCIE2F6HPv3XjcNsU6hOOY9hUSuVjQUuVWqiNf3Bq3RopeASED10VEXJNiZl8i4NlunnZvJz8yYN6jnIp2v6Bd0mhN3M8YAAAAAQErQEIPAAAAAAAiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzQEFR1IhAjJCZt6EA7OrFXoJ8feE1YevYYMcmYwVG8whu3TCsjFLIQLjvTgAmGbJ2o7EqpnMTqnGwN1G3xXGHvDOHycSkXFOV1KuAQ4gVndyHDWkJKI9bcx8kJA25QWuaGUOCdWXM7S35zADpNwBDwQAAAAAARAEAAAAAAz8CWxpZ2h0bmluZwEIK/Jiqp0i3SYAAQD2AgAAAAABAYulMzSBYSogKOBxk3Kg+HN0Hl81kGsQVuw2mwoetN33AQAAAAD9////AkBCDwAAAAAAIgAgW4zTuRTPZ83Y+mJzyTA1PdNkdnNPvZYhAsLfU7kIgM0BLw8AAAAAACJRIGP/7k6n1R5srfkIbihqJSeSKqoluMU66/MvoyoKYn9aAkcwRAIgFlrmLyNU919XilsjNJ5sxvlE36XmUmRAoDD36K8BZ+cCIE2F6HPv3XjcNsU6hOOY9hUSuVjQUuVWqiNf3Bq3RopeASED10VEXJNiZl8i4NlunnZvJz8yYN6jnIp2v6Bd0mhN3M8YAAAAAQErAS8PAAAAAAAiUSBj/+5Op9UebK35CG4oaiUnkiqqJbjFOuvzL6MqCmJ/WgEOIFZ3chw1pCSiPW3MfJCQNuUFrmhlDgnVlzO0t+cwA6TcAQ8EAQAAAAEQBP3///8M/AlsaWdodG5pbmcBCDmPhBY5ChQUAAEDCE58DQAAAAAAAQQiUSB4NjVf3IqC3EywCncsVVQVHQY4Sk3WXo0/aKwIVmuEvgz8CWxpZ2h0bmluZwEIxt4P7eqf3+QAAQMIAAAAAAAAAAABBCIAIFuM07kUz2fN2Ppic8kwNT3TZHZzT72WIQLC31O5CIDNDPwJbGlnaHRuaW5nAQji6kH6aOXoAgA="
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **psbt** (string): The (incomplete) PSBT of the splice transaction.
- **commitments\_secured** (boolean): Whether or not the commitments were secured.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "psbt": "cHNidP8BAgQCAAAAAQMEbAAAAAEEAQIBBQECAQYBAwH7BAIAAAAAAQD2AgAAAAABAYulMzSBYSogKOBxk3Kg+HN0Hl81kGsQVuw2mwoetN33AQAAAAD9////AkBCDwAAAAAAIgAgW4zTuRTPZ83Y+mJzyTA1PdNkdnNPvZYhAsLfU7kIgM0BLw8AAAAAACJRIGP/7k6n1R5srfkIbihqJSeSKqoluMU66/MvoyoKYn9aAkcwRAIgFlrmLyNU919XilsjNJ5sxvlE36XmUmRAoDD36K8BZ+cCIE2F6HPv3XjcNsU6hOOY9hUSuVjQUuVWqiNf3Bq3RopeASED10VEXJNiZl8i4NlunnZvJz8yYN6jnIp2v6Bd0mhN3M8YAAAAAQErQEIPAAAAAAAiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzQEOIFZ3chw1pCSiPW3MfJCQNuUFrmhlDgnVlzO0t+cwA6TcAQ8EAAAAAAEQBAAAAAAM/AlsaWdodG5pbmcBCCvyYqqdIt0mAAEA9gIAAAAAAQGLpTM0gWEqICjgcZNyoPhzdB5fNZBrEFbsNpsKHrTd9wEAAAAA/f///wJAQg8AAAAAACIAIFuM07kUz2fN2Ppic8kwNT3TZHZzT72WIQLC31O5CIDNAS8PAAAAAAAiUSBj/+5Op9UebK35CG4oaiUnkiqqJbjFOuvzL6MqCmJ/WgJHMEQCIBZa5i8jVPdfV4pbIzSebMb5RN+l5lJkQKAw9+ivAWfnAiBNhehz79143DbFOoTjmPYVErlY0FLlVqojX9wat0aKXgEhA9dFRFyTYmZfIuDZbp52byc/MmDeo5yKdr+gXdJoTdzPGAAAAAEBKwEvDwAAAAAAIlEgY//uTqfVHmyt+QhuKGolJ5IqqiW4xTrr8y+jKgpif1oBDiBWd3IcNaQkoj1tzHyQkDblBa5oZQ4J1ZcztLfnMAOk3AEPBAEAAAABEAT9////DPwJbGlnaHRuaW5nAQg5j4QWOQoUFAABAwhOfA0AAAAAAAEEIlEgeDY1X9yKgtxMsAp3LFVUFR0GOEpN1l6NP2isCFZrhL4M/AlsaWdodG5pbmcBCMbeD+3qn9/kAAEDCODIEAAAAAAAAQQiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzQz8CWxpZ2h0bmluZwEI4upB+mjl6AIA",
  "commitments_secured": true
}
```

AUTHOR
------

Dusty <<@dusty\_daemon>> is mainly responsible.

SEE ALSO
--------

lightning-splice\_init(7), lightning-splice\_signed(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
