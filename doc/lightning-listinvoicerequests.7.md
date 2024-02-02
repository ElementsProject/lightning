lightning-listinvoicerequests -- Command for querying invoice\_request status
=============================================================================

SYNOPSIS
--------

**listinvoicerequests** [*invreq\_id*] [*active\_only*]

DESCRIPTION
-----------

The **listinvoicerequests** RPC command gets the status of a specific `invoice_request`,
if it exists, or the status of all `invoice_requests` if given no argument.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **invoicerequests** is returned.  It is an array of objects, where each object contains:

- **invreq\_id** (hash): the SHA256 hash of all invoice\_request fields less than 160
- **active** (boolean): whether the invoice\_request is currently active
- **single\_use** (boolean): whether the invoice\_request will become inactive after we pay an invoice for it
- **bolt12** (string): the bolt12 string starting with lnr
- **used** (boolean): whether the invoice\_request has already been used
- **label** (string, optional): the label provided when creating the invoice\_request

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-invoicerequests(7), lightning-disableinvoicerequest(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:cdbdbd0dbe3776b3f6e79b88d3dc5ae3292af48234a4900e365c25663b8cdd67)
