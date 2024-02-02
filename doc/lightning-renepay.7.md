lightning-renepay -- Command for sending a payment to a BOLT11 invoice
======================================================================

SYNOPSIS
--------

**renepay** *invstring* [*amount\_msat*] [*maxfee*] [*maxdelay*]
[*retry\_for*] [*description*] [*label*]

DESCRIPTION
-----------

**renepay** is a new payment plugin based on Pickhardt-Richter optimization
method for Multi-Path-Payments. This implementation has not been thoroughly
tested and it should be used with caution.

The response will occur when the payment fails or succeeds. Once a
payment has succeeded, calls to **renepay** with the same *invstring*
will not lead to a new payment attempt, but instead it will succeed immediately.

When using *lightning-cli*, you may skip optional parameters by using
*null*. Alternatively, use **-k** option to provide parameters by name.

OPTIMALITY
----------

**renepay** is based on the work by Pickhardt-Richter's
*Optimally Reliable & Cheap Payment Flows on the Lightning Network*.
Which means the payment command will prefer routes that have a higher
probability of success while keeping fees low.

The algorithm records some partial knowledge of the state of the Network
deduced from the responses obtained after evey payment attempt.
This knowledge is kept through different payment requests, but decays with time
to account for the dynamics of the Network (after 1 hour all previous knowledge
will be erased).
Knowledge from previous payment attempts increases the reliability for
subsequent ones.

Higher probabilities of success and lower fees cannot generally by optimized at
once. Hence **renepay** combines the two in different amounts seeking solutions
that satisfy *maxfee* bound and a target for 90% probability of success.
*maxfee* is a hard bound, in the sense that the command will never attempt a
payment when the fees exceed that value. While the probability target is not
compulsory (but desirable), i.e. if the best route does not satisfy the
90% probability target it will be tried anyways.

When *maxfee* and the 90% probability bounds are satified, the algorithm will
optimize the fees to its lowest value.


RANDOMIZATION
-------------

To protect user privacy, the payment algorithm performs *shadow route*
randomization.
Which means the payment algorithm will virtually extend the route
by adding delays and fees along it, making it appear to intermediate nodes
that the route is longer than it actually is. This prevents intermediate
nodes from reliably guessing their distance from the payee.

Route randomization will never exceed *maxfee* of the payment.
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
- **amount\_msat** (msat): amount the recipient received
- **amount\_sent\_msat** (msat): total amount we sent (including fees)
- **status** (string): status of payment (one of "complete", "pending", "failed")
- **destination** (pubkey, optional): the final destination of the payment

[comment]: # (GENERATE-FROM-SCHEMA-END)

You can monitor the progress and retries of a payment using the
lightning-renepaystatus(7) command.

ERRORS
------

The following error codes may occur:

- -1: Catchall nonspecific error.
- 200: Other payment attempts are in progress.
- 203: Permanent failure at destination.
- 205: Unable to find a route.
- 206: Payment routes are too expensive.
- 207: Invoice expired. Payment took too long before expiration, or
already expired at the time you initiated payment.
- 210: Payment timed out without a payment in progress.
- 212: Invoice is invalid.

AUTHOR
------

Eduardo Quintana-Miranda <<eduardo.quintana@pm.me>> is mainly responsible.

SEE ALSO
--------

lightning-renepaystatus(7), lightning-listpays(7), lightning-invoice(7).

RESOURCES
---------

- Main web site: <https://github.com/ElementsProject/lightning>

- Pickhardt R. and Richter S., *Optimally Reliable & Cheap Payment Flows on the Lightning Network* <https://arxiv.org/abs/2107.05322>

[comment]: # ( SHA256STAMP:946ad2fc9ef6bb6dbab6613b9cb55d34ed5a15dd876efcaeaa41174f0bdc40b0)
