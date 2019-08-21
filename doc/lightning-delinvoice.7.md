LIGHTNING-DELINVOICE(7) Manual Page
===================================
lightning-delinvoice - Command for removing an invoice.

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

------------------------------------------------------------------------

Last updated 2019-04-07 14:23:17 CEST
