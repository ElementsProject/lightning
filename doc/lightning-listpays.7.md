lightning-listpays -- Command for querying payment status
=========================================================

SYNOPSIS
--------

**listpays** \[bolt11\] \[payment_hash\]

DESCRIPTION
-----------

The **listpay** RPC command gets the status of all *pay* commands, or a
single one if either *bolt11* or *payment_hash* was specified.

RETURN VALUE
------------

On success, an array of objects is returned. Each object contains:

 *bolt11*
the *bolt11* invoice if provided to `pay`.

 *payment_hash*
the *payment_hash* of the payment.

 *status*
one of *complete*, *failed* or *pending*.

 *payment\_preimage*
if *status* is *complete*.

 *label*
optional *label*, if provided to *pay* or *sendonion*.

 *amount\_sent\_msat*
total amount sent, in "NNNmsat" format.

For old payments (pre-0.7) we didn’t save the *bolt11* string, so in its
place are three other fields:

 *payment\_hash*
the hash of the *payment\_preimage* which will prove payment.

 *destination*
the final destination of the payment.

 *amount\_msat*
the amount the destination received, in "NNNmsat" format.

These three can all be extracted from *bolt11*, hence are obsolete.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-paystatus(7), lightning-listsendpays(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

