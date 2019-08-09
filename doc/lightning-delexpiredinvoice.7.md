lightning-delexpiredinvoice

7

lightning-delexpiredinvoice

Command for removing expired invoices.

**delexpiredinvoice** \[*maxexpirytime*\]

DESCRIPTION
===========

The **delexpiredinvoice** RPC command removes all invoices that have
expired on or before the given *maxexpirytime*.

If *maxexpirytime* is not specified then all expired invoices are
deleted.

RETURN VALUE
============

On success, an empty object is returned.

AUTHOR
======

ZmnSCPxj &lt;<ZmnSCPxj@protonmail.com>&gt; is mainly responsible.

SEE ALSO
========

lightning-delinvoice(7), lightning-autocleaninvoice(7)

RESOURCES
=========

Main web site: <https://github.com/ElementsProject/lightning>
