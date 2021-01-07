lightning-waitinvoice -- Command for waiting for specific payment
=================================================================

SYNOPSIS
--------

**waitinvoice** *label*

DESCRIPTION
-----------

The **waitinvoice** RPC command waits until a specific invoice is paid,
then returns that single entry as per **listinvoice**.

RETURN VALUE
------------

On success, an invoice description will be returned as per
lightning-listinvoice(7). The *status* field will be *paid* or *expired*.

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: If the invoice is deleted while unpaid, or the invoice does not exist.
- 903: If the invoice expires before being paid, or is already expired.

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly
responsible.

SEE ALSO
--------

lightning-waitanyinvoice(7), lightning-listinvoice(7),
lightning-delinvoice(7), lightning-invoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

