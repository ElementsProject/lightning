lightning-pay -- Command for sending a payment to a BOLT11 invoice
==================================================================

SYNOPSIS
--------

**pay** *bolt11* \[*msatoshi*\] \[*label*\] \[*riskfactor*\]
\[*maxfeepercent*\] \[*retry\_for*\] \[*maxdelay*\] \[*exemptfee*\]

DESCRIPTION
-----------

The **pay** RPC command attempts to find a route to the given
destination, and send the funds it asks for. If the *bolt11* does not
contain an amount, *msatoshi* is required, otherwise if it is specified
it must be *null*. *msatoshi* is in millisatoshi precision; it can be a
whole number, or a whole number with suffix *msat* or *sat*, or a three
decimal point number with suffix *sat*, or an 1 to 11 decimal point
number suffixed by *btc*.

(Note: if **experimental-offers** is enabled, *bolt11* can actually be
a bolt12 invoice, such as one received from lightningd-fetchinvoice(7)).

The *label* field is used to attach a label to payments, and is returned
in lightning-listpays(7) and lightning-listsendpays(7). The *riskfactor*
is described in detail in lightning-getroute(7), and defaults to 10. The
*maxfeepercent* limits the money paid in fees, and defaults to 0.5. The
`maxfeepercent` is a percentage of the amount that is to be paid. The `exemptfee`
option can be used for tiny payments which would be dominated by the fee
leveraged by forwarding nodes. Setting `exemptfee` allows the
`maxfeepercent` check to be skipped on fees that are smaller than
`exemptfee` (default: 5000 millisatoshi).

The response will occur when the payment fails or succeeds. Once a
payment has succeeded, calls to **pay** with the same *bolt11* will
succeed immediately.

Until *retry\_for* seconds passes (default: 60), the command will keep
finding routes and retrying the payment. However, a payment may be
delayed for up to `maxdelay` blocks by another node; clients should be
prepared for this worst case.

When using *lightning-cli*, you may skip optional parameters by using
*null*. Alternatively, use **-k** option to provide parameters by name.

RANDOMIZATION
-------------

To protect user privacy, the payment algorithm performs some
randomization.

1: Route Randomization

Route randomization means the payment algorithm does not always use the
lowest-fee or shortest route. This prevents some highly-connected node
from learning all of the user payments by reducing their fees below the
network average.

2: Shadow Route

Shadow route means the payment algorithm will virtually extend the route
by adding delays and fees along it, making it appear to intermediate nodes
that the route is longer than it actually is. This prevents intermediate
nodes from reliably guessing their distance from the payee.

Route randomization will never exceed *maxfeepercent* of the payment.
Route randomization and shadow routing will not take routes that would
exceed *maxdelay*.

RETURN VALUE
------------

On success, this returns the *payment\_preimage* which hashes to the
*payment\_hash* to prove that the payment was successful. It will also
return, a *getroute\_tries* and a *sendpay\_tries* statistics for the
number of times it internally called **getroute** and **sendpay**.

You can monitor the progress and retries of a payment using the
lightning-paystatus(7) command.

The following error codes may occur:
- -1: Catchall nonspecific error.
- 201: Already paid with this *hash* using different amount or
destination.
- 203: Permanent failure at destination. The *data* field of the error
will be routing failure object.
- 205: Unable to find a route.
- 206: Route too expensive. Either the fee or the needed total
locktime for the route exceeds your *maxfeepercent* or *maxdelay*
settings, respectively. The *data* field of the error will indicate
the actual *fee* as well as the *feepercent* percentage that the fee
has of the destination payment amount. It will also indicate the
actual *delay* along the route.
- 207: Invoice expired. Payment took too long before expiration, or
already expired at the time you initiated payment. The *data* field
of the error indicates *now* (the current time) and *expiry* (the
invoice expiration) as UNIX epoch time in seconds.
- 210: Payment timed out without a payment in progress.

Error codes 202 and 204 will only get reported at **sendpay**; in
**pay** we will keep retrying if we would have gotten those errors.

A routing failure object has the fields below:
- *erring\_index*: The index of the node along the route that reported
the error. 0 for the local node, 1 for the first hop, and so on.
- *erring\_node*: The hex string of the pubkey id of the node that
reported the error.
- *erring\_channel*: The short channel ID of the channel that has the
error, or *0:0:0* if the destination node raised the error.
- *failcode*: The failure code, as per BOLT \#4.
- *channel\_update*. The hex string of the *channel\_update* message
received from the remote node. Only present if error is from the
remote node and the *failcode* has the UPDATE bit set, as per BOLT \#4.

The *data* field of errors will include statistics *getroute\_tries* and
*sendpay\_tries*. It will also contain a *failures* field with detailed
data about routing errors.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listpays(7), lightning-decodepay(7), lightning-listinvoice(7),
lightning-delinvoice(7), lightning-getroute(7), lightning-invoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

