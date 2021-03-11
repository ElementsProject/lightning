lightning-openchannel\_signed -- Command to conclude a channel open
===================================================================

SYNOPSIS
--------

**openchannel_signed** *channel_id* *signed_psbt*

DESCRIPTION
-----------

`openchannel_signed` is a low level RPC command which concludes a channel
open with the specified peer. It uses the v2 openchannel protocol, which
allows for interactive transaction construction.

This command should be called after `openchannel_update` returns
*commitments_secured* `true`.

This command will broadcast the finalized funding transaction,
if we receive valid signatures from the peer.

*channel_id* is the id of the channel.

*signed_psbt* is the PSBT returned from `openchannel_update` (where
*commitments_secured* was true) with partial signatures or finalized
witness stacks included for every input that we contributed to the
PSBT.

RETURN VALUE
------------

On success, returns the *channel_id* for this channel; hex *tx* of the
published funding transaction; and *txid* of the funding transaction.

On error, the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 303: Funding transaction broadcast failed.
- 305: Peer is not connected.
- 309: PSBT missing required fields.
- 311: Unknown channel id.
- 312: Channel in an invalid state

SEE ALSO
--------

lightning-openchannel\_update(7), lightning-openchannel\_signed(7),
lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7),
lightning-fundchannel(7), lightning-fundpsbt(7), lightning-utxopsbt(7),
lightning-multifundchannel(7)

AUTHOR
------

@niftynei <<niftynei@gmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
