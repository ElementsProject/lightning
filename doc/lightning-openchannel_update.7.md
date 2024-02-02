lightning-openchannel\_update -- Command to update a collab channel open
========================================================================

SYNOPSIS
--------

**openchannel\_update** *channel\_id* *psbt*

DESCRIPTION
-----------

`openchannel_update` is a low level RPC command which continues an open
channel, as specified by *channel\_id*. An updated  *psbt* is passed in; any
changes from the PSBT last returned (either from `openchannel_init` or
a previous call to `openchannel_update`) will be communicated to the peer.

Must be called after `openchannel_init` and before `openchannel_signed`.

Must be called until *commitments\_secured* is returned as true, at which point
`openchannel_signed` should be called with a signed version of the PSBT
returned by the last call to `openchannel_update`.


RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **channel\_id** (hex): the channel id of the channel (always 64 characters)
- **channel\_type** (object): channel\_type as negotiated with peer *(added v24.02)*:
  - **bits** (array of u32s): Each bit set in this channel\_type *(added v24.02)*:
    - Bit number
  - **names** (array of strings): Feature name for each bit set in this channel\_type *(added v24.02)*:
    - Name of feature bit (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even")
- **psbt** (string): the PSBT of the funding transaction
- **commitments\_secured** (boolean): whether the *psbt* is complete (if true, sign *psbt* and call `openchannel_signed` to complete the channel open)
- **funding\_outnum** (u32): The index of the funding output in the psbt
- **close\_to** (hex, optional): scriptPubkey which we have to close to if we mutual close
- **requires\_confirmed\_inputs** (boolean, optional): Does peer require confirmed inputs in psbt?

[comment]: # (GENERATE-FROM-SCHEMA-END)

If *commitments\_secured* is true, will also return:

- The derived *channel\_id*.
- A *close\_to* script, iff a `close_to` address was provided to
  `openchannel_init` and the peer supports `option_upfront_shutdownscript`.
- The *funding\_outnum*, the index of the funding output for this channel
  in the funding transaction.

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

SEE ALSO
--------

lightning-openchannel\_init(7), lightning-openchannel\_signed(7),
lightning-openchannel\_bump(7), lightning-openchannel\_abort(7),
lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7),
lightning-fundchannel(7), lightning-fundpsbt(7), lightning-utxopsbt(7),
lightning-multifundchannel(7)

AUTHOR
------

@niftynei <<niftynei@gmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:13df70a54c29a3ac4b8f44a0d2f4cdc47928417b7c810bc19ec35fe820558730)
