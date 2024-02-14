lightning-delexpiredinvoice -- Command for removing expired invoices
====================================================================

SYNOPSIS
--------

**delexpiredinvoice** [*maxexpirytime*] 

DESCRIPTION
-----------

The **delexpiredinvoice** RPC command removes all invoices that have expired on or before the given *maxexpirytime*.

- **maxexpirytime** (u64, optional): Invoice expiry time in seconds. If not specified then all expired invoices are deleted.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:delexpiredinvoice#1",
  "method": "delexpiredinvoice",
  "params": {
    "maxexpirytime": null
  }
}
```

RETURN VALUE
------------

On success, an empty object is returned.

EXAMPLE JSON RESPONSE
---------------------

```json
{}
```

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-delinvoice(7), lightning-autoclean-status(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
