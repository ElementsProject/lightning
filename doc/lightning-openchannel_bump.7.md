lightning-openchannel\_bump -- Command to initiate a channel RBF
================================================================

SYNOPSIS
--------

**openchannel\_bump** *channel\_id* *amount* *initialpsbt* [*funding\_feerate*] 

DESCRIPTION
-----------

`openchannel_bump` is a RPC command which initiates a channel RBF (Replace-By-Fee) for the specified channel. It uses the openchannel protocol which allows for interactive transaction construction.

Warning: bumping a leased channel will lose the lease.

- **channel\_id** (hash): Id of the channel to RBF.
- **amount** (sat): Satoshi value that we will contribute to the channel. This value will be \_added\_ to the provided PSBT in the output which is encumbered by the 2-of-2 script for this channel.
- **initialpsbt** (string): The funded, incomplete PSBT that specifies the UTXOs and change output for our channel contribution. It can be updated, see `openchannel_update`; *initialpsbt* must have at least one input. Must have the Non-Witness UTXO (PSBT\_IN\_NON\_WITNESS\_UTXO) set for every input. An error (code 309) will be returned if this requirement is not met.
- **funding\_feerate** (feerate, optional): Feerate for the funding transaction. The default is 1/64th greater than the last feerate used for this channel.

RETURN VALUE
------------

On success, an object is returned, containing:

- **channel\_id** (hash): The channel id of the channel.
- **channel\_type** (object): Channel\_type as negotiated with peer. *(added v24.02)*:
  - **bits** (array of u32s): Each bit set in this channel\_type. *(added v24.02)*:
    - (u32, optional): Bit number.
  - **names** (array of strings): Feature name for each bit set in this channel\_type. *(added v24.02)*:
    - (string, optional) (one of "static\_remotekey/even", "anchor\_outputs/even", "anchors\_zero\_fee\_htlc\_tx/even", "scid\_alias/even", "zeroconf/even"): Name of feature bit.
- **psbt** (string): The (incomplete) PSBT of the RBF transaction.
- **commitments\_secured** (boolean) (always *false*): Whether the *psbt* is complete.
- **funding\_serial** (u64): The serial\_id of the funding output in the *psbt*.
- **requires\_confirmed\_inputs** (boolean, optional): Does peer require confirmed inputs in psbt?

If the peer does not support `option_dual_fund`, this command will return an error.

If the channel is not in a state that is eligible for RBF, this command will return an error.

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 300: The amount exceeded the maximum configured funding amount.
- 301: The provided PSBT cannot afford the funding amount.
- 305: Peer is not connected.
- 309: PSBT missing required fields
- 311: Unknown channel id.
- 312: Channel in an invalid state

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-openchannel\_init(7), lightning-openchannel\_update(7), lightning-openchannel\_signed(7), lightning-openchannel\_abort(7), lightning-fundchannel\_start(7), lightning-fundchannel\_complete(7), lightning-fundchannel(7), lightning-fundpsbt(7), lightning-utxopsbt(7), lightning-multifundchannel(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
