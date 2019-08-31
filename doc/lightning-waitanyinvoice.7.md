lightning-waitanyinvoice -- Command for waiting for payments
============================================================

SYNOPSIS
--------

**waitanyinvoice** \[*lastpay\_index*\]

DESCRIPTION
-----------

The **waitanyinvoice** RPC command waits until an invoice is paid, then
returns a single entry as per **listinvoice**. It will not return for
any invoices paid prior to or including the *lastpay\_index*.

This is usually called iteratively: once with no arguments, then
repeatedly with the returned *pay\_index* entry. This ensures that no
paid invoice is missed.

The *pay\_index* is a monotonically-increasing number assigned to an
invoice when it gets paid. The first valid *pay\_index* is 1; specifying
*lastpay\_index* of 0 equivalent to not specifying a *lastpay\_index*.
Negative *lastpay\_index* is invalid.

RETURN VALUE
------------

On success, an invoice description will be returned as per
lightning-listinvoice(7): *complete* will always be *true*.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-waitinvoice(7), lightning-listinvoice(7),
lightning-delinvoice(7), lightning-invoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
