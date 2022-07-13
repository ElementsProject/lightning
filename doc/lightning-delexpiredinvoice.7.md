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

lightning-delinvoice(7), lightning-autocleaninvoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:c71baf4b5863fd6f4d2ba21a97d4106195ba10c5add21087142b1a5ee533da91)
