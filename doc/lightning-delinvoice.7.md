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

On success, an invoice description will be returned as per
lightning-listinvoice(7).

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
