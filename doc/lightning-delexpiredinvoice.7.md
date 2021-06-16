lightning-delexpiredinvoice -- Command for removing expired invoices
====================================================================

SYNOPSIS
--------

**delexpiredinvoice** \[*maxexpirytime*\]

DESCRIPTION
-----------

The **delexpiredinvoice** RPC command removes all invoices that have
expired on or before the given *maxexpirytime*.

If *maxexpirytime* is not specified then all expired invoices are
deleted.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an empty object is returned.
[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-delinvoice(7), lightning-autocleaninvoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:644749218693cab4f48f6557a908aba66ae32f6b769576345f66ad62a6c7e7e0)
