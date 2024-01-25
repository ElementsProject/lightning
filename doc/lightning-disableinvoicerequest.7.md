lightning-disableinvoicerequest -- Command for removing an invoice request
==========================================================================

SYNOPSIS
--------
**(WARNING: experimental-offers only)**

**disableinvoicerequest** *invreq\_id*

DESCRIPTION
-----------

The **disableinvoicerequest** RPC command disables an
invoice\_request, so that no further invoices will be accepted (and
thus, no further payments made)..

We currently don't support deletion of invoice\_requests, so they are
not forgotten entirely (there may be payments which refer to this
invoice\_request).


RETURN VALUE
------------

Note: the returned object is the same format as **listinvoicerequest**.

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **invreq\_id** (hash): the SHA256 hash of all invoice\_request fields less than 160
- **active** (boolean): whether the invoice\_request is currently active (always *false*)
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

lightning-invoicerequest(7), lightning-listinvoicerequest(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:364b694d88e34dbd9e8e7c2f2d1631acbc199c14b8cdf87364b4f7c517705dbf)
