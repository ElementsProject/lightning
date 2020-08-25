lightning-autocleaninvoice -- Set up auto-delete of expired invoice
===================================================================

SYNOPSIS
--------

**autocleaninvoice** \[*cycle\_seconds*\] \[*expired\_by*\]

DESCRIPTION
-----------

The **autocleaninvoice** RPC command sets up automatic cleaning of
expired invoices.

Autoclean will be done every *cycle\_seconds* seconds. Setting
*cycle\_seconds* to 0 disables autoclean. If not specified, this
defaults to 3600 (one hour).

Every autoclean cycle, expired invoices, which have already been expired
for at least *expired\_by* seconds, will be deleted. If *expired\_by* is
not specified, this defaults to 86400 (one day).

On startup of the daemon, no autoclean is set up.

RETURN VALUE
------------

On success, an empty object is returned.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-delexpiredinvoice(7), lightning-delinvoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

