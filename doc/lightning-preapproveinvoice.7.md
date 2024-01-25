lightning-preapproveinvoice -- Ask the HSM to preapprove an invoice (low-level)
==================================================================

SYNOPSIS
--------

**preapproveinvoice** *bolt11*

DESCRIPTION
-----------

The **preapproveinvoice** RPC command submits the *bolt11* invoice to
the HSM to check that it is approved for payment.

Generally the **preapproveinvoice** request does not need to be made
explicitly, it is automatically generated as part of a **pay** request.

By default, the HSM will approve all **preapproveinvoice** requests.

If a remote signer is being used it might decline an **preapproveinvoice**
request because it would exceed velocity controls, is not covered by
allowlist controls, was declined manually, or other reasons.

If a remote signer declines a **preapproveinvoice** request a subsequent
attempt to pay the invoice anyway will fail; the signer will refuse to sign
the commitment.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an empty object is returned.

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Ken Sedgwick <<ken@bonsai.com>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:351b7e2537562036bab7c45cfa1108991ade2a9190ef902afbf9e2804cc0f466)
