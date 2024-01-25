lightning-pay -- Command for sending a payment to a BOLT11 invoice
==================================================================

SYNOPSIS
--------

**pay** *bolt11* [*amount\_msat*] [*label*] [*riskfactor*]
[*maxfeepercent*] [*retry\_for*] [*maxdelay*] [*exemptfee*]
[*localinvreqid*] [*exclude*] [*maxfee*] [*description*]

DESCRIPTION
-----------

The **pay** RPC command attempts to find a route to the given
destination, and send the funds it asks for. If the *bolt11* does not
contain an amount, *amount\_msat* is required, otherwise if it is specified
it must be *null*. *amount\_msat* is in millisatoshi precision; it can be a
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

`localinvreqid` is used by offers to link a payment attempt to a local
`invoice_request` offer created by lightningd-invoicerequest(7).  This ensures
that we only make a single payment for an offer, and that the offer is
marked `used` once paid.

*maxfee* overrides both *maxfeepercent* and *exemptfee* defaults (and
if you specify *maxfee* you cannot specify either of those), and
creates an absolute limit on what fee we will pay.  This allows you to
implement your own heuristics rather than the primitive ones used
here.

*description* is only required for bolt11 invoices which do not
contain a description themselves, but contain a description hash:
in this case *description* is required.
*description* is then checked against the hash inside the invoice
before it will be paid.

The response will occur when the payment fails or succeeds. Once a
payment has succeeded, calls to **pay** with the same *bolt11* will
succeed immediately.

Until *retry\_for* seconds passes (default: 60), the command will keep
finding routes and retrying the payment. However, a payment may be
delayed for up to `maxdelay` blocks by another node; clients should be
prepared for this worst case.

*exclude* is a JSON array of short-channel-id/direction (e.g. [
"564334x877x1/0", "564195x1292x0/1" ]) or node-id which should be excluded
from consideration for routing. The default is not to exclude any channels
or nodes.

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

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **payment\_preimage** (secret): the proof of payment: SHA256 of this **payment\_hash**
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **created\_at** (number): the UNIX timestamp showing when this payment was initiated
- **parts** (u32): how many attempts this took
- **amount\_msat** (msat): Amount the recipient received
- **amount\_sent\_msat** (msat): Total amount we sent (including fees)
- **status** (string): status of payment (one of "complete", "pending", "failed")
- **destination** (pubkey, optional): the final destination of the payment

The following warnings may also be returned:

- **warning\_partial\_completion**: Not all parts of a multi-part payment have completed

[comment]: # (GENERATE-FROM-SCHEMA-END)

You can monitor the progress and retries of a payment using the
lightning-paystatus(7) command.

The following error codes may occur:

- -1: Catchall nonspecific error.
- 201: Already paid with this *hash* using different amount or
destination.
- 203: Permanent failure at destination. The *data* field of the error
will be routing failure object (except for self-payment, which currently returns the error directly from lightning-sendpay(7)).
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

[comment]: # ( SHA256STAMP:1d2a7a9867493439268aa1b6036f5d23bdfe9337ca3a29463997c9ccdb11b95f)
