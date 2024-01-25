lightning-autoclean-status -- Examine auto-delete of old invoices/payments/forwards
===================================================================================

SYNOPSIS
--------

**autoclean-status** [*subsystem*]

DESCRIPTION
-----------

The **autoclean-status** RPC command tells you about the status of
the autclean plugin, optionally for only one subsystem.

The subsystems currently supported are:

* `failedforwards`: routed payments which did not succeed (`failed` or `local_failed` in listforwards `status`).
* `succeededforwards`: routed payments which succeeded (`settled` in listforwards `status`).
* `failedpays`: payment attempts which did not succeed (`failed` in listpays `status`).
* `succededpays`: payment attempts which succeeded (`complete` in listpays `status`).
* `expiredinvoices`: invoices which were not paid (and cannot be) (`expired` in listinvoices `status`).
* `paidinvoices`: invoices which were paid (`paid` in listinvoices `status).

RETURN VALUE
------------

Note that the ages parameters are set by various `autoclean-...-age`
parameters in your configuration: see lightningd-config(5).

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **autoclean** is returned.  It is an object containing:

- **succeededforwards** (object, optional):
  - **enabled** (boolean): whether autocleaning is enabled for successful listforwards
  - **cleaned** (u64): total number of deletions done (ever)

  If **enabled** is *true*:

    - **age** (u64): age (in seconds) to delete successful listforwards
- **failedforwards** (object, optional):
  - **enabled** (boolean): whether autocleaning is enabled for failed listforwards
  - **cleaned** (u64): total number of deletions done (ever)

  If **enabled** is *true*:

    - **age** (u64): age (in seconds) to delete failed listforwards
- **succeededpays** (object, optional):
  - **enabled** (boolean): whether autocleaning is enabled for successful listpays/listsendpays
  - **cleaned** (u64): total number of deletions done (ever)

  If **enabled** is *true*:

    - **age** (u64): age (in seconds) to delete successful listpays/listsendpays
- **failedpays** (object, optional):
  - **enabled** (boolean): whether autocleaning is enabled for failed listpays/listsendpays
  - **cleaned** (u64): total number of deletions done (ever)

  If **enabled** is *true*:

    - **age** (u64): age (in seconds) to delete failed listpays/listsendpays
- **paidinvoices** (object, optional):
  - **enabled** (boolean): whether autocleaning is enabled for paid listinvoices
  - **cleaned** (u64): total number of deletions done (ever)

  If **enabled** is *true*:

    - **age** (u64): age (in seconds) to paid listinvoices
- **expiredinvoices** (object, optional):
  - **enabled** (boolean): whether autocleaning is enabled for expired (unpaid) listinvoices
  - **cleaned** (u64): total number of deletions done (ever)

  If **enabled** is *true*:

    - **age** (u64): age (in seconds) to expired listinvoices

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightningd-config(5), lightning-listinvoices(7),
lightning-listpays(7), lightning-listforwards(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:8706bbc3b69f4160ad40fd116556ce699b6d70122b39c20effc27930fe7eec49)
