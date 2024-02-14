lightning-preapprovekeysend -- Ask the HSM to preapprove a keysend payment (low-level)
======================================================================================

SYNOPSIS
--------

**preapprovekeysend** *destination* *payment\_hash* *amount\_msat* 

DESCRIPTION
-----------

Command *added* in v23.02.

The **preapprovekeysend** RPC command submits the *destination*, *payment\_hash*, and *amount\_msat* parameters to the HSM to check that they are approved as a keysend payment.

Generally the **preapprovekeysend** request does not need to be made explicitly, it is automatically generated as part of a **keysend** request.

By default, the HSM will approve all **preapprovekeysend** requests.

If a remote signer is being used it might decline an **preapprovekeysend** request because it would exceed velocity controls, is not covered by allowlist controls, was declined manually, or other reasons.

If a remote signer declines a **preapprovekeysend** request a subsequent attempt to pay the keysend anyway will fail; the signer will refuse to sign the commitment.

- **destination** (pubkey): It is a 33 byte, hex-encoded, node ID of the node that the payment should go to. *(added v23.02)*
- **payment\_hash** (hex) (always 64 characters): It is the unique identifier of a payment. *(added v23.02)*
- **amount\_msat** (msat): The amount to send in millisatoshi precision; it can be a whole number, or a whole number with suffix `msat` or `sat`, or a three decimal point number with suffix `sat`, or an 1 to 11 decimal point number suffixed by `btc`. *(added v23.02)*

RETURN VALUE
------------

On success, an empty object is returned.

AUTHOR
------

Ken Sedgwick <<ken@bonsai.com>> is mainly responsible.

SEE ALSO
--------

lightning-keysend(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
