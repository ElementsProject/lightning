lightning-sendpay -- Low-level command for sending a payment via a route
========================================================================

SYNOPSIS
--------

**sendpay** *route* *payment\_hash* [*label*] [*amount\_msat*]
[*bolt11*] [*payment\_secret*] [*partid*] [*localinvreqid*] [*groupid*]
[*payment\_metadata*] [*description*]

DESCRIPTION
-----------

The **sendpay** RPC command attempts to send funds associated with the
given *payment\_hash*, along a route to the final destination in the
route.

Generally, a client would call lightning-getroute(7) to resolve a route,
then use **sendpay** to send it. If it fails, it would call
lightning-getroute(7) again to retry.

The response will occur when the payment is on its way to the
destination. The **sendpay** RPC command does not wait for definite
success or definite failure of the payment. Instead, use the
**waitsendpay** RPC command to poll or wait for definite success or
definite failure.

The *label* and *bolt11* parameters, if provided, will be returned in
*waitsendpay* and *listsendpays* results.

The *amount\_msat* amount must be provided if *partid* is non-zero, otherwise
it must be equal to the final
amount to the destination. By default it is in millisatoshi precision; it can be a whole number, or a whole number
ending in *msat* or *sat*, or a number with three decimal places ending
in *sat*, or a number with 1 to 11 decimal places ending in *btc*.

The *payment\_secret* is the value that the final recipient requires to
accept the payment, as defined by the `payment_data` field in BOLT 4
and the `s` field in the BOLT 11 invoice format.  It is required if
*partid* is non-zero.

The *partid* value, if provided and non-zero, allows for multiple parallel
partial payments with the same *payment\_hash*.  The *amount\_msat* amount
(which must be provided) for each **sendpay** with matching
*payment\_hash* must be equal, and **sendpay** will fail if there are

The *localinvreqid* value indicates that this payment is being made for a local
invoice\_request: this ensures that we only send a payment for a single-use
invoice\_request once.

*groupid* allows you to attach a number which appears in **listsendpays** so
payments can be identified as part of a logical group.  The *pay* plugin uses
this to identify one attempt at a MPP payment, for example.

*payment\_metadata* is placed in the final onion hop TLV.

Once a payment has succeeded, calls to **sendpay** with the same
*payment\_hash* but a different *amount\_msat* or destination will fail;
this prevents accidental multiple payments. Calls to **sendpay** with
the same *payment\_hash*, *amount\_msat*, and destination as a previous
successful payment (even if a different route or *partid*) will return immediately
with success.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **id** (u64): unique ID for this payment attempt
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment (always 64 characters)
- **status** (string): status of the payment (could be complete if already sent previously) (one of "pending", "complete")
- **created\_at** (u64): the UNIX timestamp showing when this payment was initiated
- **amount\_sent\_msat** (msat): The amount sent
- **groupid** (u64, optional): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment\_hash
- **amount\_msat** (msat, optional): The amount delivered to destination (if known)
- **destination** (pubkey, optional): the final destination of the payment if known
- **completed\_at** (u64, optional): the UNIX timestamp showing when this payment was completed
- **label** (string, optional): the *label*, if given to sendpay
- **partid** (u64, optional): the *partid*, if given to sendpay
- **bolt11** (string, optional): the bolt11 string (if supplied)
- **bolt12** (string, optional): the bolt12 string (if supplied: **experimental-offers** only).

If **status** is "complete":

  - **payment\_preimage** (secret): the proof of payment: SHA256 of this **payment\_hash** (always 64 characters)

If **status** is "pending":

  - **message** (string): Monitor status with listpays or waitsendpay

[comment]: # (GENERATE-FROM-SCHEMA-END)

On error, if the error occurred from a node other than the final
destination, the route table will be updated so that
lightning-getroute(7) should return an alternate route (if any). An
error from the final destination implies the payment should not be
retried.

The following error codes may occur:
-   -1: Catchall nonspecific error.
-   201: Already paid with this *hash* using different amount or
    destination.
-   202: Unparseable onion reply. The *data* field of the error will
    have an *onionreply* field, a hex string representation of the raw
    onion reply.
-   203: Permanent failure at destination. The *data* field of the error
    will be routing failure object.
-   204: Failure along route; retry a different route. The *data* field
    of the error will be routing failure object.
-   212: *localinvreqid* refers to an invalid, or used, local invoice\_request.

A routing failure object has the fields below:
-   *erring\_index*. The index of the node along the route that reported
    the error. 0 for the local node, 1 for the first hop, and so on.
-   *erring\_node*. The hex string of the pubkey id of the node that
    reported the error.
-   *erring\_channel*. The short channel ID of the channel that has
    the error, or *0:0:0* if the destination node raised the error. In
    addition *erring\_direction* will indicate which direction of the
    channel caused the failure.
-   *failcode*. The failure code, as per BOLT \#4.
-   *channel\_update*. The hex string of the *channel\_update* message
    received from the remote node. Only present if error is from the
    remote node and the *failcode* has the UPDATE bit set, as per BOLT
    \#4.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoice(7), lightning-delinvoice(7),
lightning-getroute(7), lightning-invoice(7), lightning-pay(7),
lightning-waitsendpay(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:b7f1a5efd80156722e5f9cca6f291306fcd22ab7b9b2754beac880f2ae5a7418)
