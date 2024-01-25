lightning-delinvoice -- Command for removing an invoice (or just its description)
=================================================================================

SYNOPSIS
--------

**delinvoice** *label* *status* [*desconly*]

DESCRIPTION
-----------

The **delinvoice** RPC command removes an invoice with *status* as given
in **listinvoices**, or with *desconly* set, removes its description.

The caller should be particularly aware of the error case caused by the
*status* changing just before this command is invoked!

If *desconly* is set, the invoice is not deleted, but has its
description removed (this can save space with very large descriptions,
as would be used with lightning-invoice(7) *deschashonly*.

RETURN VALUE
------------

Note: The return is the same as an object from lightning-listinvoice(7).

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **label** (string): Unique label given at creation time
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **created\_index** (u64): 1-based index indicating order this invoice was created in *(added v23.08)*
- **status** (string): State of invoice (one of "paid", "expired", "unpaid")
- **expires\_at** (u64): UNIX timestamp when invoice expires (or expired)
- **bolt11** (string, optional): BOLT11 string
- **bolt12** (string, optional): BOLT12 string
- **amount\_msat** (msat, optional): the amount required to pay this invoice
- **description** (string, optional): description used in the invoice
- **updated\_index** (u64, optional): 1-based index indicating order this invoice was changed (only present if it has changed since creation) *(added v23.08)*

If **bolt12** is present:

  - **local\_offer\_id** (hex, optional): offer for which this invoice was created
  - **invreq\_payer\_note** (string, optional): the optional *invreq\_payer\_note* from invoice\_request which created this invoice

If **status** is "paid":

  - **pay\_index** (u64): unique index for this invoice payment
  - **amount\_received\_msat** (msat): how much was actually received
  - **paid\_at** (u64): UNIX timestamp of when payment was received
  - **payment\_preimage** (secret): SHA256 of this is the *payment\_hash* offered in the invoice

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The following errors may be reported:

- -1:  Database error.
- 905:  An invoice with that label does not exist.
- 906:  The invoice *status* does not match the parameter.
  An error object will be returned as error *data*, containing
  *current\_status* and *expected\_status* fields.
  This is most likely due to the *status* of the invoice
  changing just before this command is invoked.
- 908: The invoice already has no description, and *desconly* was set.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoice(7), lightning-waitinvoice(7),
lightning-invoice(7), lightning-delexpiredinvoice(7),
lightning-autoclean-status(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:de866707ddf6d47a646cf83f7c190a9f09f623d6d4e39dab01357c0074f6566c)
