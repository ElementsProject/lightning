lightning-openchannel\_update -- Command to update a collab channel open
========================================================================

SYNOPSIS
--------

**openchannel\_update** *channel\_id* *psbt* 

DESCRIPTION
-----------

`openchannel_update` is a low level RPC command which continues an open channel, as specified by *channel\_id*. An updated *psbt* is passed in; any changes from the PSBT last returned (either from `openchannel_init` or a previous call to `openchannel_update`) will be communicated to the peer.

Must be called after `openchannel_init` and before `openchannel_signed`.

Must be called until *commitments\_secured* is returned as true, at which point `openchannel_signed` should be called with a signed version of the PSBT returned by the last call to `openchannel_update`.

- **channel\_id** (hash): Id of the channel.
- **psbt** (string): Updated PSBT to be sent to the peer. May be identical to the PSBT last returned by either `openchannel_init` or `openchannel_update`.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:openchannel_update#1",
  "method": "openchannel_update",
  "params": {
    "channel_id": "c3a282c1136f44dc2e499c116a9d9e6ea64649c3eabdd396cb96fb30a86fad8e",
    "psbt": "cHNidP8BAgQCAAAAAQMEZgAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQDeAgAAAAABAdWZZguGlQJ1eA+d7WAT500jdCzHJWT9J/TGQIkbS1KfAAAAAAD9////AoCWmAEAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WXzWm0oAQAAABYAFE8Xxp4GJggW2lJcsHg0VLolc/Z/AkcwRAIgEQLtA2JvAk7S1R9QD5o4SVNXCjMwTUIyHtu65taC/d4CIEnpq2PdrqKqitdmZj09U8cFuwV+Ba9kmZSUsctSWx8CASECUKP6EBufpaBXT910uYhCcKdw9z8iqHgyKa3uuX2QgmVlAAAAAQEfgJaYAQAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQEOIAVmgyf8sA3N9J6XaH5z7W+GUPDFOM/2L/PuD7iE0RaqAQ8EAAAAAAEQBP3///8M/AlsaWdodG5pbmcBCH932EuFXyxeAAEDCEBCDwAAAAAAAQQiACA/FzDCfUe+WFEBa+aPSY4TZTYt6liPHz5OHo04w2gQ3wz8CWxpZ2h0bmluZwEI42voJCAYLKQA"
  }
}
{
  "id": "example:openchannel_update#2",
  "method": "openchannel_update",
  "params": {
    "channel_id": "c3a282c1136f44dc2e499c116a9d9e6ea64649c3eabdd396cb96fb30a86fad8e",
    "psbt": "cHNidP8BAgQCAAAAAQMEZgAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQDeAgAAAAABAdWZZguGlQJ1eA+d7WAT500jdCzHJWT9J/TGQIkbS1KfAAAAAAD9////AoCWmAEAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WXzWm0oAQAAABYAFE8Xxp4GJggW2lJcsHg0VLolc/Z/AkcwRAIgEQLtA2JvAk7S1R9QD5o4SVNXCjMwTUIyHtu65taC/d4CIEnpq2PdrqKqitdmZj09U8cFuwV+Ba9kmZSUsctSWx8CASECUKP6EBufpaBXT910uYhCcKdw9z8iqHgyKa3uuX2QgmVlAAAAAQEfgJaYAQAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQEOIAVmgyf8sA3N9J6XaH5z7W+GUPDFOM/2L/PuD7iE0RaqAQ8EAAAAAAEQBP3///8M/AlsaWdodG5pbmcBCH932EuFXyxeAAEDCEBCDwAAAAAAAQQiACA/FzDCfUe+WFEBa+aPSY4TZTYt6liPHz5OHo04w2gQ3wz8CWxpZ2h0bmluZwEI42voJCAYLKQA"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **channel\_id** (hash): The channel id of the channel.
- **channel\_type** (object): Channel\_type as negotiated with peer. *(added v24.02)*:
  - **bits** (array of u32s): Each bit set in this channel\_type. *(added v24.02)*:
    - (u32, optional): Bit number.
  - **names** (array of strings): Feature name for each bit set in this channel\_type. *(added v24.02)*:
    - (string, optional) (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even"): Name of feature bit.
- **psbt** (string): The PSBT of the funding transaction.
- **commitments\_secured** (boolean): Whether the *psbt* is complete (if true, sign *psbt* and call `openchannel_signed` to complete the channel open).
- **funding\_outnum** (u32): The index of the funding output in the psbt.
- **close\_to** (hex, optional): Scriptpubkey which we have to close to if we mutual close.
- **requires\_confirmed\_inputs** (boolean, optional): Does peer require confirmed inputs in psbt?

If **commitments\_secured** is *true*:
  - **channel\_id** (hash): The derived channel id.
  - **funding\_outnum** (u32): The index of the funding output for this channel in the funding transaction.
  - **close\_to** (hex, optional): If a `close_to` address was provided to `openchannel_init` and the peer supports `option_upfront_shutdownscript`.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "channel_id": "c3a282c1136f44dc2e499c116a9d9e6ea64649c3eabdd396cb96fb30a86fad8e",
  "psbt": "cHNidP8BAgQCAAAAAQMEZgAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQDeAgAAAAABAdWZZguGlQJ1eA+d7WAT500jdCzHJWT9J/TGQIkbS1KfAAAAAAD9////AoCWmAEAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WXzWm0oAQAAABYAFE8Xxp4GJggW2lJcsHg0VLolc/Z/AkcwRAIgEQLtA2JvAk7S1R9QD5o4SVNXCjMwTUIyHtu65taC/d4CIEnpq2PdrqKqitdmZj09U8cFuwV+Ba9kmZSUsctSWx8CASECUKP6EBufpaBXT910uYhCcKdw9z8iqHgyKa3uuX2QgmVlAAAAAQEfgJaYAQAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQEOIAVmgyf8sA3N9J6XaH5z7W+GUPDFOM/2L/PuD7iE0RaqAQ8EAAAAAAEQBP3///8M/AlsaWdodG5pbmcBCH932EuFXyxeAAEDCEBCDwAAAAAAAQQiACA/FzDCfUe+WFEBa+aPSY4TZTYt6liPHz5OHo04w2gQ3wz8CWxpZ2h0bmluZwEI42voJCAYLKQA",
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
  "commitments_secured": true,
  "funding_outnum": 0
}
{
  "channel_id": "c3a282c1136f44dc2e499c116a9d9e6ea64649c3eabdd396cb96fb30a86fad8e",
  "psbt": "cHNidP8BAgQCAAAAAQMEZgAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQDeAgAAAAABAdWZZguGlQJ1eA+d7WAT500jdCzHJWT9J/TGQIkbS1KfAAAAAAD9////AoCWmAEAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WXzWm0oAQAAABYAFE8Xxp4GJggW2lJcsHg0VLolc/Z/AkcwRAIgEQLtA2JvAk7S1R9QD5o4SVNXCjMwTUIyHtu65taC/d4CIEnpq2PdrqKqitdmZj09U8cFuwV+Ba9kmZSUsctSWx8CASECUKP6EBufpaBXT910uYhCcKdw9z8iqHgyKa3uuX2QgmVlAAAAAQEfgJaYAQAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQEOIAVmgyf8sA3N9J6XaH5z7W+GUPDFOM/2L/PuD7iE0RaqAQ8EAAAAAAEQBP3///8M/AlsaWdodG5pbmcBCH932EuFXyxeAAEDCEBCDwAAAAAAAQQiACA/FzDCfUe+WFEBa+aPSY4TZTYt6liPHz5OHo04w2gQ3wz8CWxpZ2h0bmluZwEI42voJCAYLKQA",
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
  "commitments_secured": true,
  "funding_outnum": 0,
  "close_to": "5120eed745804da9784cc203f563efa99ffa54fdf01b137bc964e63c3124070ffbe6"
}
```

ERRORS
------

On error, the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 305: Peer is not connected.
- 309: PSBT missing required fields
- 311: Unknown channel id.
- 312: Channel in an invalid state

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-openchannel\_init(7), lightning-openchannel\_signed(7), lightning-openchannel\_bump(7), lightning-openchannel\_abort(7), lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7), lightning-fundchannel(7), lightning-fundpsbt(7), lightning-utxopsbt(7), lightning-multifundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
