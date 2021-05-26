lightning-delinvoice -- Command for removing an invoice
=======================================================

SYNOPSIS
--------

**delinvoice** *label* *status*

DESCRIPTION
-----------

The **delinvoice** RPC command removes an invoice with *status* as given
in **listinvoices**.

The caller should be particularly aware of the error case caused by the
*status* changing just before this command is invoked!

RETURN VALUE
------------

Note: The return is the same as an object from lightning-listinvoice(7).

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **label** (string): Unique label given at creation time
- **status** (string): State of invoice (one of "paid", "expired", "unpaid")
- **expires_at** (u64): UNIX timestamp when invoice expires (or expired)
- **bolt11** (string, optional): BOLT11 string
- **bolt12** (string, optional): BOLT12 string

If **bolt12** is present:
  - **local_offer_id** (hex, optional): offer for which this invoice was created

If **status** is "paid":
  - **pay_index** (u64): unique index for this invoice payment
  - **amount_received_msat** (msat): how much was actually received
  - **paid_at** (u64): UNIX timestamp of when payment was received
  - **payment_preimage** (hex): SHA256 of this is the *payment_hash* offered in the invoice (always 64 characters)
[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The following errors may be reported:

- -1:  Database error.
- 905:  An invoice with that label does not exist.
- 906:  The invoice *status* does not match the parameter.
  An error object will be returned as error *data*, containing
  *current_status* and *expected_status* fields.
  This is most likely due to the *status* of the invoice
  changing just before this command is invoked.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoice(7), lightning-waitinvoice(7),
lightning-invoice(7), lightning-delexpiredinvoice(7),
lightning-autocleaninvoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:8cd84ec57d229dacb6d6c52510334da87846f1c8eea7db286063a2513e8318cb)
