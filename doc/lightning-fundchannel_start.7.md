lightning-fundchannel\_start -- Command for initiating channel establishment for a lightning channel
====================================================================================================

SYNOPSIS
--------

**fundchannel\_start** *id* *amount* [*feerate*] [*announce*] [*close\_to*] [*push\_msat*] [*channel\_type*]

DESCRIPTION
-----------

`fundchannel_start` is a lower level RPC command. It allows a user to
initiate channel establishment with a connected peer.

*id* is the node id of the remote peer.

*amount* is the satoshi value that the channel will be funded at. This
value MUST be accurate, otherwise the negotiated commitment transactions
will not encompass the correct channel value.

*feerate* is an optional field. Sets the feerate for subsequent
commitment transactions: see **fundchannel**.  Note that this is ignored
for channels with *option\_anchors\_zero\_fee\_htlc\_tx* (we always use a low
commitment fee for these).

*announce* whether or not to announce this channel.

*close\_to* is a Bitcoin address to which the channel funds should be sent to
on close. Only valid if both peers have negotiated `option_upfront_shutdown_script`.
Returns `close_to` set to closing script iff is negotiated.

*push\_msat* is the amount of millisatoshis to push to the channel peer at
open. Note that this is a gift to the peer -- these satoshis are
added to the initial balance of the peer at channel start and are largely
unrecoverable once pushed.

*channel\_type* *(added v24.02)* is an array of bit numbers, representing the explicit
channel type to request.  BOLT 2 defines the following value types:

```
The currently defined basic types are:
  - no features (no bits set) `[]`
  - `option_static_remotekey` (`[12]`)
  - `option_anchor_outputs` and `option_static_remotekey` (`[20, 12]`)
  - `option_anchors_zero_fee_htlc_tx` and `option_static_remotekey` ([22, 12])

Each basic type has the following variations allowed:
  - `option_scid_alias` ([46])
  - `option_zeroconf` ([50])
```

Note that the funding transaction MUST NOT be broadcast until after
channel establishment has been successfully completed by running
`fundchannel_complete`, as the commitment transactions for this channel
are not secured until the complete command succeeds. Broadcasting
transaction before that can lead to unrecoverable loss of funds.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **funding\_address** (string): The address to send funding to for the channel. DO NOT SEND COINS TO THIS ADDRESS YET.
- **scriptpubkey** (hex): The raw scriptPubkey for the address
- **close\_to** (hex, optional): The raw scriptPubkey which mutual close will go to; only present if *close\_to* parameter was specified and peer supports `option_upfront_shutdown_script`
- **mindepth** (u32, optional): Number of confirmations before we consider the channel active.

The following warnings may also be returned:

- **warning\_usage**: A warning not to prematurely broadcast the funding transaction (always present!)

[comment]: # (GENERATE-FROM-SCHEMA-END)

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 300: The amount exceeded the maximum configured funding amount.
- 301: The provided `push_msat` is greater than the provided `amount`.
- 304: Still syncing with bitcoin network
- 305: Peer is not connected.
- 306: Unknown peer id.

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel(7), lightning-multifundchannel(7),
lightning-fundchannel\_complete(7), lightning-fundchannel\_cancel(7)
lightning-openchannel\_init(7), lightning-openchannel\_update(7),
lightning-openchannel\_signed(7), lightning-openchannel\_bump(7),
lightning-openchannel\_abort(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:8d9c42f4424065f442b6ae5eb5624e4a4c2cb2e73649faf9c9547b8fc12803ee)
