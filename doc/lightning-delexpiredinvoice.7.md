lightning-delexpiredinvoice -- Command for removing expired invoices
====================================================================

SYNOPSIS
--------

**delexpiredinvoice** [*maxexpirytime*]

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

lightning-delinvoice(7), lightning-autoclean-status(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:bea6cd45f3e8c912180dd76a69a13a2f1d2ba88adab001cfa161700cfc8288b4)
