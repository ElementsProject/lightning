lightning-listsendpays -- Low-level command for querying sendpay status
=======================================================================

SYNOPSIS
--------

**listsendpays** \[*bolt11*\] \[*payment\_hash*\]

DESCRIPTION
-----------

The **listsendpays** RPC command gets the status of all *sendpay*
commands (which is also used by the *pay* command), or with *bolt11* or
*payment\_hash* limits results to that specific payment. You cannot
specify both.

Note that in future there may be more than one concurrent *sendpay*
command per *pay*, so this command should be used with caution.

RETURN VALUE
------------

On success, an array of objects is returned, ordered by increasing *id*. Each object contains:

 *id*
unique internal value assigned at creation

 *payment\_hash*
the hash of the *payment\_preimage* which will prove payment.

 *destination*
the final destination of the payment.

 *amount\_msat*
the amount the destination received, in "NNNmsat" format.

 *created\_at*
the UNIX timestamp showing when this payment was initiated.

 *status*
one of *complete*, *failed* or *pending*.

 *payment\_preimage*
(if *status* is *complete*) proves payment was received.

 *label*
optional *label*, if provided to *sendpay*.

 *bolt11*
the *bolt11* argument given to *pay* (may be missing for pre-0.7
payments).

 *bolt12*
if **experimental-offers** is enabled, and `pay` was a given a bolt12
invoice, this field will appear instead of *bolt11*.

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly
responsible.

SEE ALSO
--------

lightning-listpays(7), lightning-sendpay(7), lightning-listinvoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

