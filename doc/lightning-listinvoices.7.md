lightning-listinvoices -- Command for querying invoice status
=============================================================

SYNOPSIS
--------

**listinvoices** \[*label*\] \[*invstring*\] \[*payment_hash*\]

DESCRIPTION
-----------

The **listinvoices** RPC command gets the status of a specific invoice,
if it exists, or the status of all invoices if given no argument.

A specific invoice can be queried by providing either the `label`
provided when creating the invoice, the `invstring` string representing
the invoice, or the `payment_hash` of the invoice. Only one of the
query parameters can be used at once.

RETURN VALUE
------------

On success, an array *invoices* of objects is returned. Each object contains
*label*, *description*, *payment\_hash*, *status* (one of *unpaid*, *paid* or *expired*),
*payment\_preimage* (for paid invoices), and *expires\_at* (a UNIX
timestamp).  If the *msatoshi* argument to lightning-invoice(7) was not "any",
there will be an *msatoshi* field as a number, and *amount\_msat* as the same
number ending in *msat*.  If the invoice was created with a bolt11 string,
there will be a *bolt11* field.
If the invoice *status* is *paid*, there will be a
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

