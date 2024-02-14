lightning-autoclean-status -- Examine auto-delete of old invoices/payments/forwards
===================================================================================

SYNOPSIS
--------

**autoclean-status** [*subsystem*] 

DESCRIPTION
-----------

The **autoclean-status** RPC command tells you about the status of the autclean plugin, optionally for only one subsystem.

- **subsystem** (string, optional) (one of "succeededforwards", "failedforwards", "succeededpays", "failedpays", "paidinvoices", "expiredinvoices"): What subsystem to ask about. Currently supported subsystems are:
     * `failedforwards`: routed payments which did not succeed (`failed` or `local_failed` in listforwards `status`).
     * `succeededforwards`: routed payments which succeeded (`settled` in listforwards `status`).
     * `failedpays`: payment attempts which did not succeed (`failed` in listpays `status`).
     * `succeededpays`: payment attempts which succeeded (`complete` in listpays `status`).
     * `expiredinvoices`: invoices which were not paid (and cannot be) (`expired` in listinvoices `status`).
     * `paidinvoices`: invoices which were paid (`paid` in listinvoices status).

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:autoclean-status#1",
  "method": "autoclean-status",
  "params": {
    "subsystem": "expiredinvoices"
  }
}
{
  "id": "example:autoclean-status#2",
  "method": "autoclean-status",
  "params": {
    "subsystem": null
  }
}
```

RETURN VALUE
------------

Note that the ages parameters are set by various `autoclean-...-age` parameters in your configuration: see lightningd-config(5).
On success, an object containing **autoclean** is returned. It is an object containing:

- **succeededforwards** (object, optional):
  - **enabled** (boolean): Whether autocleaning is enabled for successful listforwards.
  - **cleaned** (u64): Total number of deletions done (ever).

  If **enabled** is *true*:
    - **age** (u64): Age (in seconds) to delete successful listforwards.
- **failedforwards** (object, optional):
  - **enabled** (boolean): Whether autocleaning is enabled for failed listforwards.
  - **cleaned** (u64): Total number of deletions done (ever).

  If **enabled** is *true*:
    - **age** (u64): Age (in seconds) to delete failed listforwards.
- **succeededpays** (object, optional):
  - **enabled** (boolean): Whether autocleaning is enabled for successful listpays/listsendpays.
  - **cleaned** (u64): Total number of deletions done (ever).

  If **enabled** is *true*:
    - **age** (u64): Age (in seconds) to delete successful listpays/listsendpays.
- **failedpays** (object, optional):
  - **enabled** (boolean): Whether autocleaning is enabled for failed listpays/listsendpays.
  - **cleaned** (u64): Total number of deletions done (ever).

  If **enabled** is *true*:
    - **age** (u64): Age (in seconds) to delete failed listpays/listsendpays.
- **paidinvoices** (object, optional):
  - **enabled** (boolean): Whether autocleaning is enabled for paid listinvoices.
  - **cleaned** (u64): Total number of deletions done (ever).

  If **enabled** is *true*:
    - **age** (u64): Age (in seconds) to paid listinvoices.
- **expiredinvoices** (object, optional):
  - **enabled** (boolean): Whether autocleaning is enabled for expired (unpaid) listinvoices.
  - **cleaned** (u64): Total number of deletions done (ever).

  If **enabled** is *true*:
    - **age** (u64): Age (in seconds) to expired listinvoices.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "autoclean": {
    "expiredinvoices": {
      "enabled": false,
      "cleaned": 0
    }
  }
}
{
  "autoclean": {
    "succeededforwards": {
      "enabled": false,
      "cleaned": 0
    },
    "failedforwards": {
      "enabled": false,
      "cleaned": 0
    },
    "succeededpays": {
      "enabled": false,
      "cleaned": 0
    },
    "failedpays": {
      "enabled": false,
      "cleaned": 0
    },
    "paidinvoices": {
      "enabled": false,
      "cleaned": 0
    },
    "expiredinvoices": {
      "enabled": true,
      "age": 2,
      "cleaned": 0
    }
  }
}
```

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightningd-config(5), lightning-listinvoices(7), lightning-listpays(7), lightning-listforwards(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
