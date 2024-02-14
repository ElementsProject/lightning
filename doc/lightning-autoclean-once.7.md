lightning-autoclean-once -- A single deletion of old invoices/payments/forwards
===============================================================================

SYNOPSIS
--------

**autoclean-once** *subsystem* *age* 

DESCRIPTION
-----------

The **autoclean-once** RPC command tell the `autoclean` plugin to do a single sweep to delete old entries. This is a manual alternative (or addition) to the various `autoclean-...-age` parameters which cause autoclean to run once per hour: see lightningd-config(5).

- **subsystem** (string) (one of "succeededforwards", "failedforwards", "succeededpays", "failedpays", "paidinvoices", "expiredinvoices"): What subsystem to clean. Currently supported subsystems are:
     * `failedforwards`: routed payments which did not succeed (`failed` or `local_failed` in listforwards `status`).
     * `succeededforwards`: routed payments which succeeded (`settled` in listforwards `status`).
     * `failedpays`: payment attempts which did not succeed (`failed` in listpays `status`).
     * `succeededpays`: payment attempts which succeeded (`complete` in listpays `status`).
     * `expiredinvoices`: invoices which were not paid (and cannot be) (`expired` in listinvoices `status`).
     * `paidinvoices`: invoices which were paid (`paid` in listinvoices status).
- **age** (u64): Non-zero number in seconds. How many seconds old an entry must be to delete it.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:autoclean-once#1",
  "method": "autoclean-once",
  "params": [
    "failedpays",
    1
  ]
}
{
  "id": "example:autoclean-once#2",
  "method": "autoclean-once",
  "params": [
    "succeededpays",
    1
  ]
}
```

RETURN VALUE
------------

On success, an object containing **autoclean** is returned. It is an object containing:

- **succeededforwards** (object, optional):
  - **cleaned** (u64): Total number of deletions done this run.
  - **uncleaned** (u64): The total number of entries *not* deleted this run.
- **failedforwards** (object, optional):
  - **cleaned** (u64): Total number of deletions done this run.
  - **uncleaned** (u64): The total number of entries *not* deleted this run.
- **succeededpays** (object, optional):
  - **cleaned** (u64): Total number of deletions done this run.
  - **uncleaned** (u64): The total number of entries *not* deleted this run.
- **failedpays** (object, optional):
  - **cleaned** (u64): Total number of deletions done this run.
  - **uncleaned** (u64): The total number of entries *not* deleted this run.
- **paidinvoices** (object, optional):
  - **cleaned** (u64): Total number of deletions done this run.
  - **uncleaned** (u64): The total number of entries *not* deleted this run.
- **expiredinvoices** (object, optional):
  - **cleaned** (u64): Total number of deletions done this run.
  - **uncleaned** (u64): The total number of entries *not* deleted this run.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "autoclean": {
    "failedpays": {
      "cleaned": 1,
      "uncleaned": 1
    }
  }
}
{
  "autoclean": {
    "succeededpays": {
      "cleaned": 1,
      "uncleaned": 0
    }
  }
}
```

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightningd-config(5), lightning-autoclean-status(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
