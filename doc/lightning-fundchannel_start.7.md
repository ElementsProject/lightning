lightning-fundchannel\_start -- Command for initiating channel establishment for a lightning channel
====================================================================================================

SYNOPSIS
--------

**fundchannel\_start** *id* *amount* [*feerate* *announce* *close\_to* *push\_msat* *channel\_type* *mindepth* *reserve*] 

DESCRIPTION
-----------

`fundchannel_start` is a lower level RPC command. It allows a user to initiate channel establishment with a connected peer.

Note that the funding transaction MUST NOT be broadcast until after channel establishment has been successfully completed by running `fundchannel_complete`, as the commitment transactions for this channel are not secured until the complete command succeeds. Broadcasting transaction before that can lead to unrecoverable loss of funds.

- **id** (pubkey): The peer id obtained from connect.
- **amount** (sat): Satoshi value that the channel will be funded at. This value MUST be accurate, otherwise the negotiated commitment transactions will not encompass the correct channel value.
- **feerate** (feerate, optional): Feerate for subsequent commitment transactions: see **fundchannel**. Note that this is ignored for channels with *option\_anchors\_zero\_fee\_htlc\_tx* (we always use a low commitment fee for these).
- **announce** (boolean, optional): Whether or not to announce this channel.
- **close\_to** (string, optional): Bitcoin address to which the channel funds should be sent to on close. Only valid if both peers have negotiated `option_upfront_shutdown_script`. Returns `close_to` set to closing script iff is negotiated.
- **push\_msat** (msat, optional): Amount of millisatoshis to push to the channel peer at open. Note that this is a gift to the peer -- these satoshis are added to the initial balance of the peer at channel start and are largely unrecoverable once pushed.
- **mindepth** (u32, optional): Number of confirmations required before we consider the channel active.
- **reserve** (msat, optional): The amount we want the peer to maintain on its side.
- **channel\_type** (array of u32s, optional): Each bit set in this channel\_type.:
  - (u32, optional): Bit number.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:fundchannel_start#1",
  "method": "fundchannel_start",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    "amount": 16777216,
    "feerate": null,
    "announce": true,
    "close_to": null,
    "mindepth": null
  }
}
{
  "id": "example:fundchannel_start#2",
  "method": "fundchannel_start",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    "amount": "100000sat",
    "feerate": null,
    "announce": true,
    "close_to": null,
    "mindepth": null,
    "channel_type": null
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **funding\_address** (string): The address to send funding to for the channel. DO NOT SEND COINS TO THIS ADDRESS YET.
- **scriptpubkey** (hex): The raw scriptPubkey for the address.
- **channel\_type** (object, optional): Channel\_type as negotiated with peer. *(added v24.02)*:
  - **bits** (array of u32s): Each bit set in this channel\_type. *(added v24.02)*:
    - (u32, optional): Bit number.
  - **names** (array of strings): Feature name for each bit set in this channel\_type. *(added v24.02)*:
    - (string, optional) (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even"): Name of feature bit.
- **close\_to** (hex, optional): The raw scriptPubkey which mutual close will go to; only present if *close\_to* parameter was specified and peer supports `option_upfront_shutdown_script`.
- **mindepth** (u32, optional): Number of confirmations before we consider the channel active.

The following warnings may also be returned:

- **warning\_usage**: A warning not to prematurely broadcast the funding transaction (always present!).

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "funding_address": "bcrt1qtwxd8wg5eanumk86vfeujvp48hfkgannf77evggzct048wggsrxsum2pmm",
  "scriptpubkey": "00205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cd",
  "warning_usage": "The funding transaction MUST NOT be broadcast until after channel establishment has been successfully completed by running `fundchannel_complete`"
}
{
  "funding_address": "bcrt1qtwxd8wg5eanumk86vfeujvp48hfkgannf77evggzct048wggsrxsum2pmm",
  "scriptpubkey": "00205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cd",
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
  "warning_usage": "The funding transaction MUST NOT be broadcast until after channel establishment has been successfully completed by running `fundchannel_complete`"
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 300: The amount exceeded the maximum configured funding amount.
- 301: The provided `push_msat` is greater than the provided `amount`.
- 304: Still syncing with bitcoin network
- 305: Peer is not connected.
- 306: Unknown peer id.
- 312: Peer negotiated `option_dual_fund`, must use `openchannel_init` not `fundchannel_start`. (Only if ``experimental-dual-fund is enabled)

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel(7), lightning-multifundchannel(7), lightning-fundchannel\_complete(7), lightning-fundchannel\_cancel(7), lightning-openchannel\_init(7), lightning-openchannel\_update(7), lightning-openchannel\_signed(7), lightning-openchannel\_bump(7), lightning-openchannel\_abort(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
