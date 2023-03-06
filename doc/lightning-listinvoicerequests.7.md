lightning-listinvoicerequests -- Command for querying invoice\_request status
=============================================================================

SYNOPSIS
--------

**listinvoicerequests** [*invreq\_id*] [*active\_only*]

DESCRIPTION
-----------

The **listinvoicerequests** RPC command gets the status of a specific `invoice_request`,
if it exists, or the status of all `invoice_requests` if given no argument.

A specific invoice can be queried by providing the `invreq_id`, which
is presented by lightning-invoicerequest(7), or can be calculated from
a bolt12 invoice.  If `active_only` is `true` (default is `false`) then
only active invoice\_requests are returned.

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

[comment]: # ( SHA256STAMP:233e28e40752d6e8db2eb7928a1ced18bf16db1dddfe6c16d0f3a32b5e51ccd4)
