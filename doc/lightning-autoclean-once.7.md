lightning-autoclean-once -- A single deletion of old invoices/payments/forwards
===============================================================================

SYNOPSIS
--------

**autoclean-once** *subsystem* *age*

DESCRIPTION
-----------

The **autoclean-once** RPC command tell the `autoclean` plugin to do a
single sweep to delete old entries.  This is a manual alternative (or
addition) to the various `autoclean-...-age` parameters which
cause autoclean to run once per hour: see lightningd-config(5).

The *subsystem*s currently supported are:

* `failedforwards`: routed payments which did not succeed (`failed` or `local_failed` in listforwards `status`).
* `succeededforwards`: routed payments which succeeded (`settled` in listforwards `status`).
* `failedpays`: payment attempts which did not succeed (`failed` in listpays `status`).
* `succededpays`: payment attempts which succeeded (`complete` in listpays `status`).
* `expiredinvoices`: invoices which were not paid (and cannot be) (`expired` in listinvoices `status`).
* `paidinvoices`: invoices which were paid (`paid` in listinvoices `status).

*age* is a non-zero number in seconds.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **autoclean** is returned.  It is an object containing:

- **succeededforwards** (object, optional):
  - **cleaned** (u64): total number of deletions done this run
  - **uncleaned** (u64): the total number of entries *not* deleted this run
- **failedforwards** (object, optional):
  - **cleaned** (u64): total number of deletions done this run
  - **uncleaned** (u64): the total number of entries *not* deleted this run
- **succeededpays** (object, optional):
  - **cleaned** (u64): total number of deletions done this run
  - **uncleaned** (u64): the total number of entries *not* deleted this run
- **failedpays** (object, optional):
  - **cleaned** (u64): total number of deletions done this run
  - **uncleaned** (u64): the total number of entries *not* deleted this run
- **paidinvoices** (object, optional):
  - **cleaned** (u64): total number of deletions done this run
  - **uncleaned** (u64): the total number of entries *not* deleted this run
- **expiredinvoices** (object, optional):
  - **cleaned** (u64): total number of deletions done this run
  - **uncleaned** (u64): the total number of entries *not* deleted this run

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightningd-config(5), lightning-autoclean-status(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:c6f69b86958274c082aeb4a6154173f65644315a0f5912820803afecfece8635)
