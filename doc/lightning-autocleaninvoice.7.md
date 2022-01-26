lightning-autocleaninvoice -- Set up auto-delete of expired invoice
===================================================================

SYNOPSIS
--------

**autocleaninvoice** [*cycle\_seconds*] [*expired\_by*]

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

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **enabled** (boolean): whether invoice autocleaning is active

If **enabled** is *true*:
  - **expired_by** (u64): how long an invoice must be expired (seconds) before we delete it
  - **cycle_seconds** (u64): how long an invoice must be expired (seconds) before we delete it

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-delexpiredinvoice(7), lightning-delinvoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:4506a00326dbfa7d44cbf891ad31cbfa66351d852aa0c58735bae03d32938edb)
