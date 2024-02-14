lightning-splice\_init -- Command to initiate a channel to a peer
=================================================================

SYNOPSIS
--------

**(WARNING: experimental-splicing only)**

**splice\_init** *channel\_id* *relative\_amount* [*initialpsbt*] [*feerate\_per\_kw*] [*force\_feerate*] 

DESCRIPTION
-----------

Command *added* in v23.08.

`splice_init` is a low level RPC command which initiates a channel splice for a given channel specified by `channel_id`.

- **channel\_id** (hash): The channel id of the channel to be spliced.
- **relative\_amount** (integer): A positive or negative amount of satoshis to add or subtract from the channel. Note you may need to add a double dash (--) after splice\_init if using a negative *relative\_amount* so it is not interpretted as a command modifier. For example: ```shell lightning-cli splice_init -- $CHANNEL_ID -100000 ```.
- **initialpsbt** (string, optional): The (optional) base 64 encoded PSBT to begin with. If not specified, one will be generated automatically.
- **feerate\_per\_kw** (u32, optional): The miner fee we promise our peer to pay for our side of the splice transaction. It is calculated by `feerate_per_kw` * our\_bytes\_in\_splice\_tx / 1000.
- **force\_feerate** (boolean, optional): By default splices will fail if the fee provided looks too high. This is to protect against accidentally setting your fee higher than intended. Set `force_feerate` to true to skip this saftey check.

EXAMPLE USAGE
-------------

Here is an example set of splice commands that will splice in 100,000 sats to the first channel that comes out of `listpeerchannels`. The example assumes you already have at least one confirmed channel.

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

RESULT=$(lightning-cli signpsbt -k psbt="$PSBT")
PSBT=$(echo $RESULT | jq -r ".signed_psbt")
echo $RESULT

lightning-cli splice_signed $CHANNEL_ID $PSBT
```

Here is an example set of splice commands that will splice out 100,000 sats from first channel that comes out of `listpeerchannels`. The example assumes you already have at least one confirmed channel.

```shell
RESULT=$(lightning-cli listpeerchannels)
CHANNEL_ID=$(echo $RESULT| jq -r ".channels[0].channel_id")
echo $RESULT

RESULT=$(lightning-cli addpsbtoutput 100000)
INITIALPSBT=$(echo $RESULT | jq -r ".psbt")
echo $RESULT

RESULT=$(lightning-cli splice_init -- $CHANNEL_ID -100500 $INITIALPSBT)
PSBT=$(echo $RESULT | jq -r ".psbt")
echo $RESULT

RESULT=$(lightning-cli splice_update $CHANNEL_ID $PSBT)
PSBT=$(echo $RESULT | jq -r ".psbt")
echo $RESULT

lightning-cli splice_signed $CHANNEL_ID $PSBT
```

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:splice_init#1",
  "method": "splice_init",
  "params": {
    "channel_id": "5677721c35a424a23d6dcc7c909036e505ae68650e09d59733b4b7e73003a4dc",
    "relative_amount": 100000,
    "initialpsbt": "cHNidP8BAF4CAAAAAVZ3chw1pCSiPW3MfJCQNuUFrmhlDgnVlzO0t+cwA6TcAQAAAAD9////AU58DQAAAAAAIlEgeDY1X9yKgtxMsAp3LFVUFR0GOEpN1l6NP2isCFZrhL5sAAAAAAEA9gIAAAAAAQGLpTM0gWEqICjgcZNyoPhzdB5fNZBrEFbsNpsKHrTd9wEAAAAA/f///wJAQg8AAAAAACIAIFuM07kUz2fN2Ppic8kwNT3TZHZzT72WIQLC31O5CIDNAS8PAAAAAAAiUSBj/+5Op9UebK35CG4oaiUnkiqqJbjFOuvzL6MqCmJ/WgJHMEQCIBZa5i8jVPdfV4pbIzSebMb5RN+l5lJkQKAw9+ivAWfnAiBNhehz79143DbFOoTjmPYVErlY0FLlVqojX9wat0aKXgEhA9dFRFyTYmZfIuDZbp52byc/MmDeo5yKdr+gXdJoTdzPGAAAAAEBKwEvDwAAAAAAIlEgY//uTqfVHmyt+QhuKGolJ5IqqiW4xTrr8y+jKgpif1oAAA==",
    "feerate_per_kw": null
  }
}
{
  "id": "example:splice_init#2",
  "method": "splice_init",
  "params": {
    "channel_id": "a40bb442dab0231b51d8f842d95aad548aa35e1d13c4cfcf2997344f805453a1",
    "relative_amount": -105000,
    "initialpsbt": "cHNidP8BAgQCAAAAAQMEbAAAAAEEAQABBQEBAQYBAwH7BAIAAAAAAQMIoIYBAAAAAAABBCJRIHg2NV/cioLcTLAKdyxVVBUdBjhKTdZejT9orAhWa4S+AA==",
    "feerate_per_kw": null
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **psbt** (string): The (incomplete) PSBT of the splice transaction.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "psbt": "cHNidP8BAgQCAAAAAQMEbAAAAAEEAQIBBQECAQYBAwH7BAIAAAAAAQD2AgAAAAABAYulMzSBYSogKOBxk3Kg+HN0Hl81kGsQVuw2mwoetN33AQAAAAD9////AkBCDwAAAAAAIgAgW4zTuRTPZ83Y+mJzyTA1PdNkdnNPvZYhAsLfU7kIgM0BLw8AAAAAACJRIGP/7k6n1R5srfkIbihqJSeSKqoluMU66/MvoyoKYn9aAkcwRAIgFlrmLyNU919XilsjNJ5sxvlE36XmUmRAoDD36K8BZ+cCIE2F6HPv3XjcNsU6hOOY9hUSuVjQUuVWqiNf3Bq3RopeASED10VEXJNiZl8i4NlunnZvJz8yYN6jnIp2v6Bd0mhN3M8YAAAAAQErQEIPAAAAAAAiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzQEFR1IhAjJCZt6EA7OrFXoJ8feE1YevYYMcmYwVG8whu3TCsjFLIQLjvTgAmGbJ2o7EqpnMTqnGwN1G3xXGHvDOHycSkXFOV1KuAQ4gVndyHDWkJKI9bcx8kJA25QWuaGUOCdWXM7S35zADpNwBDwQAAAAAARAEAAAAAAz8CWxpZ2h0bmluZwEIK/Jiqp0i3SYAAQD2AgAAAAABAYulMzSBYSogKOBxk3Kg+HN0Hl81kGsQVuw2mwoetN33AQAAAAD9////AkBCDwAAAAAAIgAgW4zTuRTPZ83Y+mJzyTA1PdNkdnNPvZYhAsLfU7kIgM0BLw8AAAAAACJRIGP/7k6n1R5srfkIbihqJSeSKqoluMU66/MvoyoKYn9aAkcwRAIgFlrmLyNU919XilsjNJ5sxvlE36XmUmRAoDD36K8BZ+cCIE2F6HPv3XjcNsU6hOOY9hUSuVjQUuVWqiNf3Bq3RopeASED10VEXJNiZl8i4NlunnZvJz8yYN6jnIp2v6Bd0mhN3M8YAAAAAQErAS8PAAAAAAAiUSBj/+5Op9UebK35CG4oaiUnkiqqJbjFOuvzL6MqCmJ/WgEOIFZ3chw1pCSiPW3MfJCQNuUFrmhlDgnVlzO0t+cwA6TcAQ8EAQAAAAEQBP3///8M/AlsaWdodG5pbmcBCDmPhBY5ChQUAAEDCE58DQAAAAAAAQQiUSB4NjVf3IqC3EywCncsVVQVHQY4Sk3WXo0/aKwIVmuEvgz8CWxpZ2h0bmluZwEIxt4P7eqf3+QAAQMIAAAAAAAAAAABBCIAIFuM07kUz2fN2Ppic8kwNT3TZHZzT72WIQLC31O5CIDNDPwJbGlnaHRuaW5nAQji6kH6aOXoAgA="
}
{
  "psbt": "cHNidP8BAgQCAAAAAQMEbAAAAAEEAQEBBQECAQYBAwH7BAIAAAAAAQD2AgAAAAABARzi7RBt64yrfqRL2p+KiUw8cYtiKICRFHmp/4eCSemSAQAAAAD9////AkBCDwAAAAAAIgAgW4zTuRTPZ83Y+mJzyTA1PdNkdnNPvZYhAsLfU7kIgM0BLw8AAAAAACJRIGP/7k6n1R5srfkIbihqJSeSKqoluMU66/MvoyoKYn9aAkcwRAIgTCjR9L+TfzP7pLJVVto5egTRbRNj/RaBhyrA3UW0aEcCIAJO5FZjXvdpRcGR949C4DnfHs3soklTjn/1upkia+TgASED10VEXJNiZl8i4NlunnZvJz8yYN6jnIp2v6Bd0mhN3M9mAAAAAQErQEIPAAAAAAAiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzQEFR1IhAjJCZt6EA7OrFXoJ8feE1YevYYMcmYwVG8whu3TCsjFLIQLjvTgAmGbJ2o7EqpnMTqnGwN1G3xXGHvDOHycSkXFOV1KuAQ4gpAu0QtqwIxtR2PhC2VqtVIqjXh0TxM/PKZc0T4BUU6EBDwQAAAAAARAEAAAAAAz8CWxpZ2h0bmluZwEIn2Ac8fyFEJwAAQMIAAAAAAAAAAABBCIAIFuM07kUz2fN2Ppic8kwNT3TZHZzT72WIQLC31O5CIDNDPwJbGlnaHRuaW5nAQgu7JK9IpBWOAABAwighgEAAAAAAAEEIlEgeDY1X9yKgtxMsAp3LFVUFR0GOEpN1l6NP2isCFZrhL4M/AlsaWdodG5pbmcBCOZ1GpRwbKfuAA=="
}
```

AUTHOR
------

Dusty <<@dusty\_daemon>> is mainly responsible.

SEE ALSO
--------

lightning-splice\_signed(7), lightning-splice\_update(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
