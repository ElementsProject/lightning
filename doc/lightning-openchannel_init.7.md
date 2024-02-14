lightning-openchannel\_init -- Command to initiate a channel to a peer
======================================================================

SYNOPSIS
--------

**openchannel\_init** *id* *amount* *initialpsbt* [*commitment\_feerate*] [*funding\_feerate*] [*announce*] [*close\_to*] [*request\_amt*] [*compact\_lease*] [*channel\_type*] 

DESCRIPTION
-----------

`openchannel_init` is a low level RPC command which initiates a channel open with a specified peer. It uses the openchannel protocol which allows for interactive transaction construction.

- **id** (pubkey): Node id of the remote peer.
- **amount** (sat): Satoshi value that we will contribute to the channel. This value will be \_added\_ to the provided PSBT in the output which is encumbered by the 2-of-2 script for this channel.
- **initialpsbt** (string): Funded, incomplete PSBT that specifies the UTXOs and change output for our channel contribution. It can be updated, see `openchannel_update`; *initialpsbt* must have at least one input. Must have the Non-Witness UTXO (PSBT\_IN\_NON\_WITNESS\_UTXO) set for every input. An error (code 309) will be returned if this requirement is not met.
- **commitment\_feerate** (feerate, optional): Feerate for commitment transactions for non-anchor channels: see **fundchannel**. For anchor channels, it is ignored.
- **funding\_feerate** (feerate, optional): Feerate for the funding transaction. The default is 'opening' feerate.
- **announce** (boolean, optional): Whether or not to announce this channel.
- **close\_to** (string, optional): Bitcoin address to which the channel funds should be sent on close. Only valid if both peers have negotiated `option_upfront_shutdown_script`.
- **request\_amt** (msat, optional): An amount of liquidity you'd like to lease from the peer. If peer supports `option_will_fund`, indicates to them to include this much liquidity into the channel. Must also pass in *compact\_lease*.
- **compact\_lease** (hex, optional): A compact representation of the peer's expected channel lease terms. If the peer's terms don't match this set, we will fail to open the channel.
- **channel\_type** (array of u32s, optional): Each bit set in this channel\_type.:
  - (u32, optional): Bit number.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:openchannel_init#1",
  "method": "openchannel_init",
  "params": {
    "id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
    "amount": 999000,
    "initialpsbt": "cHNidP8BADMCAAAAAYbThUhSzYr7ph6Z434bdcW7eoirYOFMmUt2GXZ79sF/AQAAAAD9////AGYAAAAAAQDeAgAAAAABARVD4QKlmwy8SNcNypf1o9TzbIFZjj4dqVzHAL0SLDoTAAAAAAD9////AjOv9ikBAAAAFgAUXJGglH7At5HOVY4ZHp0+19kv655AQg8AAAAAABYAFAH62Qq81maX4lkhZHIt5KlevuFlAkcwRAIgVIxRXqIykOOxm/6YPaFFx2Qh1618qlXPUhDiliVQ2KUCIHQcHniUTcm1XT8SyRE8ev52jm0uiIYum15XcR/tPh+NASEC3Pby7xL4+Ig/Z8TchQ0QT1upLGet3da8qjSjgHO9LOJlAAAAAQEfQEIPAAAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQA=",
    "commitment_feerate": null,
    "funding_feerate": null,
    "announce": true,
    "close_to": null,
    "request_amt": null,
    "channel_type": [
      12,
      22
    ]
  }
}
{
  "id": "example:openchannel_init#2",
  "method": "openchannel_init",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    "amount": 16777216,
    "initialpsbt": "cHNidP8BADMCAAAAAQVmgyf8sA3N9J6XaH5z7W+GUPDFOM/2L/PuD7iE0RaqAAAAAAD9////AGYAAAAAAQDeAgAAAAABAdWZZguGlQJ1eA+d7WAT500jdCzHJWT9J/TGQIkbS1KfAAAAAAD9////AoCWmAEAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WXzWm0oAQAAABYAFE8Xxp4GJggW2lJcsHg0VLolc/Z/AkcwRAIgEQLtA2JvAk7S1R9QD5o4SVNXCjMwTUIyHtu65taC/d4CIEnpq2PdrqKqitdmZj09U8cFuwV+Ba9kmZSUsctSWx8CASECUKP6EBufpaBXT910uYhCcKdw9z8iqHgyKa3uuX2QgmVlAAAAAQEfgJaYAQAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQA=",
    "commitment_feerate": null,
    "funding_feerate": null,
    "announce": true,
    "close_to": null,
    "request_amt": null,
    "channel_type": null
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **channel\_id** (hash): The channel id of the channel.
- **psbt** (string): The (incomplete) PSBT of the funding transaction.
- **channel\_type** (object): Channel\_type as negotiated with peer. *(added v24.02)*:
  - **bits** (array of u32s): Each bit set in this channel\_type. *(added v24.02)*:
    - (u32, optional): Bit number.
  - **names** (array of strings): Feature name for each bit set in this channel\_type. *(added v24.02)*:
    - (string, optional) (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even"): Name of feature bit.
- **commitments\_secured** (boolean) (always *false*): Whether the *psbt* is complete.
- **funding\_serial** (u64): The serial\_id of the funding output in the *psbt*.
- **requires\_confirmed\_inputs** (boolean, optional): Does peer require confirmed inputs in psbt?

If the peer does not support `option_dual_fund`, this command will return an error.

If you sent a *request\_amt* and the peer supports `option_will_fund` and is interested in leasing you liquidity in this channel, returns their updated channel fee max (*channel\_fee\_proportional\_basis*, *channel\_fee\_base\_msat*), updated rate card for the lease fee (*lease\_fee\_proportional\_basis*, *lease\_fee\_base\_sat*) and their on-chain weight *weight\_charge*, which will be added to the lease fee at a rate of *funding\_feerate* * *weight\_charge* / 1000.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "channel_id": "53fa2b1ca0d8f21abeaaac0495ab9925cdfaf2ca8b04dbe4aeb061823e1ff2c8",
  "psbt": "cHNidP8BAgQCAAAAAQMEZgAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQDeAgAAAAABARVD4QKlmwy8SNcNypf1o9TzbIFZjj4dqVzHAL0SLDoTAAAAAAD9////AjOv9ikBAAAAFgAUXJGglH7At5HOVY4ZHp0+19kv655AQg8AAAAAABYAFAH62Qq81maX4lkhZHIt5KlevuFlAkcwRAIgVIxRXqIykOOxm/6YPaFFx2Qh1618qlXPUhDiliVQ2KUCIHQcHniUTcm1XT8SyRE8ev52jm0uiIYum15XcR/tPh+NASEC3Pby7xL4+Ig/Z8TchQ0QT1upLGet3da8qjSjgHO9LOJlAAAAAQEfQEIPAAAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQEOIIbThUhSzYr7ph6Z434bdcW7eoirYOFMmUt2GXZ79sF/AQ8EAQAAAAEQBP3///8M/AlsaWdodG5pbmcBCMCDK/6LyRi8AAEDCFg+DwAAAAAAAQQiACDYM+8ZRsbTj0OCG/yzqLt2buFQn9LuMPDZqFFcgmCmfAz8CWxpZ2h0bmluZwEIchtFHfZ5FBgA",
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
  "commitments_secured": false,
  "funding_serial": 8222241539686471000,
  "requires_confirmed_inputs": false
}
{
  "channel_id": "252d1b0a1e57895e84137f28cf19ab2c35847e284c112fefdecc7afeaa5c1de7",
  "psbt": "cHNidP8BAgQCAAAAAQMEZgAAAAEEAQEBBQEBAQYBAwH7BAIAAAAAAQDeAgAAAAABAdWZZguGlQJ1eA+d7WAT500jdCzHJWT9J/TGQIkbS1KfAAAAAAD9////AoCWmAEAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WXzWm0oAQAAABYAFE8Xxp4GJggW2lJcsHg0VLolc/Z/AkcwRAIgEQLtA2JvAk7S1R9QD5o4SVNXCjMwTUIyHtu65taC/d4CIEnpq2PdrqKqitdmZj09U8cFuwV+Ba9kmZSUsctSWx8CASECUKP6EBufpaBXT910uYhCcKdw9z8iqHgyKa3uuX2QgmVlAAAAAQEfgJaYAQAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZQEOIAVmgyf8sA3N9J6XaH5z7W+GUPDFOM/2L/PuD7iE0RaqAQ8EAAAAAAEQBP3///8M/AlsaWdodG5pbmcBCLR8RjOq9lmcAAEDCAAAAAEAAAAAAQQiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzQz8CWxpZ2h0bmluZwEIZZtc7LD4y9YA",
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
  "commitments_secured": false,
  "funding_serial": 7321547790872006000,
  "requires_confirmed_inputs": false
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 300: The amount exceeded the maximum configured funding amount.
- 301: The provided PSBT cannot afford the funding amount.
- 304: Still syncing with bitcoin network
- 305: Peer is not connected.
- 306: Unknown peer id.
- 309: PSBT missing required fields
- 310: v2 channel open protocol not supported by peer
- 312: Channel in an invalid state

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-openchannel\_update(7), lightning-openchannel\_signed(7), lightning-openchannel\_abort(7), lightning-openchannel\_bump(7), lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7), lightning-fundchannel(7), lightning-fundpsbt(7), lightning-utxopsbt(7), lightning-multifundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
