lightning-waitsendpay -- Command for sending a payment via a route
==================================================================

SYNOPSIS
--------

**waitsendpay** *payment\_hash* \[*timeout*\] \[*partid*\]

DESCRIPTION
-----------

The **waitsendpay** RPC command polls or waits for the status of an
outgoing payment that was initiated by a previous **sendpay**
invocation.

The *partid* argument must match that of the **sendpay** command.

Optionally the client may provide a *timeout*, an integer in seconds,
for this RPC command to return. If the *timeout* is provided and the
given amount of time passes without the payment definitely succeeding or
definitely failing, this command returns with a 200 error code (payment
still in progress). If *timeout* is not provided this call will wait
indefinitely.

Indicating a *timeout* of 0 effectively makes this call a pollable query
of the status of the payment.

If the payment completed with success, this command returns with
success. Otherwise, if the payment completed with failure, this command
returns an error.

RETURN VALUE
------------

On success, an object similar to the output of **listsendpays** will be
returned. This object will have a *status* field that is the string
*"complete"*.

On error, and even if the error occurred from a node other than the
final destination, the route table will no longer be updated. Use the
*exclude* parameter of the `getroute` command to ignore the failing
route.

The following error codes may occur:
-   -1: Catchall nonspecific error.
-   200: Timed out before the payment could complete.
-   202: Unparseable onion reply. The *data* field of the error will
    have an *onionreply* field, a hex string representation of the raw
    onion reply.
-   203: Permanent failure at destination. The *data* field of the error
    will be routing failure object.
-   204: Failure along route; retry a different route. The *data* field
    of the error will be routing failure object.
-   208: A payment for *payment\_hash* was never made and there is
    nothing to wait for.
-   209: The payment already failed, but the reason for failure was not
    stored. This should only occur when querying failed payments on very
    old databases.

A routing failure object has the fields below:
-   *erring\_index*: The index of the node along the route that reported
    the error. 0 for the local node, 1 for the first hop, and so on.
-   *erring\_node*: The hex string of the pubkey id of the node that
    reported the error.
-   *erring\_channel*: The short channel ID of the channel that has the
    error (or the final channel if the destination raised the error).
-   *erring\_direction*: The direction of traversing the
    *erring\_channel*:
-   *failcode*: The failure code, as per BOLT \#4.
-   *failcodename*: The human-readable name corresponding to *failcode*,
    if known.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-sendpay(7), lightning-pay(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

