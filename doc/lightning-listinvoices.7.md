lightning-listinvoices -- Command for querying invoice status
=============================================================

SYNOPSIS
--------

**listinvoices** \[*label*\]

DESCRIPTION
-----------

The **listinvoices** RPC command gets the status of a specific invoice,
if it exists, or the status of all invoices if given no argument.

RETURN VALUE
------------

On success, an array *invoices* of objects is returned. Each object contains
*label*, *payment\_hash*, *status* (one of *unpaid*, *paid* or *expired*),
*payment\_preimage* (for paid invoices), and *expiry\_time* (a UNIX
timestamp).  If the *msatoshi* argument to lightning-invoice(7) was not "any",
there will be an *msatoshi* field as a number, and *amount\_msat* as the same
number ending in *msat*. If the invoice *status* is *paid*, there will be a
*pay\_index* field and an *msatoshi\_received* field (which may be slightly
greater than *msatoshi* as some overpaying is permitted to allow clients to
obscure payment paths); there will also be an *amount\_received\_msat* field
with the same number as *msatoshi\_received* but ending in *msat*.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-waitinvoice(7), lightning-delinvoice(7), lightning-invoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

