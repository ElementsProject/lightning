lightning-disableinvoicerequest -- Command for removing an invoice request
==========================================================================

SYNOPSIS
--------

**(WARNING: experimental-offers only)**

**disableinvoicerequest** *invreq\_id* 

DESCRIPTION
-----------

Command *added* in v22.11.

The **disableinvoicerequest** RPC command disables an invoice\_request, so that no further invoices will be accepted (and thus, no further payments made)..

We currently don't support deletion of invoice\_requests, so they are not forgotten entirely (there may be payments which refer to this invoice\_request).

- **invreq\_id** (string): A specific invoice can be disabled by providing the `invreq_id`, which is presented by lightning-invoicerequest(7).

RETURN VALUE
------------

Note: the returned object is the same format as **listinvoicerequest**.
On success, an object is returned, containing:

- **invreq\_id** (hash): The SHA256 hash of all invoice\_request fields less than 160.
- **active** (boolean) (always *false*): Whether the invoice\_request is currently active.
- **single\_use** (boolean): Whether the invoice\_request will become inactive after we pay an invoice for it.
- **bolt12** (string): The bolt12 string starting with lnr.
- **used** (boolean): Whether the invoice\_request has already been used.
- **label** (string, optional): The label provided when creating the invoice\_request.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-invoicerequest(7), lightning-listinvoicerequest(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
