lightning-invoice -- Command for accepting payments
===================================================

SYNOPSIS
--------

**invoice** *amount\_msat* *label* *description* [*expiry*]
[*fallbacks*] [*preimage*] [*exposeprivatechannels*] [*cltv*] [*deschashonly*]

DESCRIPTION
-----------

The **invoice** RPC command creates the expectation of a payment of a
given amount of milli-satoshi: it returns a unique token which another
lightning daemon can use to pay this invoice. This token includes a
*route hint* description of an incoming channel with capacity to pay the
invoice, if any exists.

The *amount\_msat* parameter can be the string "any", which creates an
invoice that can be paid with any amount. Otherwise it is a positive value in
millisatoshi precision; it can be a whole number, or a whole number
ending in *msat* or *sat*, or a number with three decimal places ending
in *sat*, or a number with 1 to 11 decimal places ending in *btc*.

The *label* must be a unique string or number (which is treated as a
string, so "01" is different from "1"); it is never revealed to other
nodes on the lightning network, but it can be used to query the status
of this invoice.

The *description* is a short description of purpose of payment, e.g. *1
cup of coffee*. This value is encoded into the BOLT11 invoice and is
viewable by any node you send this invoice to (unless *deschashonly* is
true as described below). It must be UTF-8, and cannot use *\\u* JSON
escape codes.

The *expiry* is optionally the time the invoice is valid for, in seconds.
If no value is provided the default of 604800 (1 week) is used.

The *fallbacks* array is one or more fallback addresses to include in
the invoice (in order from most-preferred to least): note that these
arrays are not currently tracked to fulfill the invoice.

The *preimage* is a 64-digit hex string to be used as payment preimage
for the created invoice. By default, if unspecified, lightningd will
generate a secure pseudorandom preimage seeded from an appropriate
entropy source on your system. **IMPORTANT**: if you specify the
*preimage*, you are responsible, to ensure appropriate care for
generating using a secure pseudorandom generator seeded with sufficient
entropy, and keeping the preimage secret. This parameter is an advanced
feature intended for use with cutting-edge cryptographic protocols and
should not be used unless explicitly needed.

If specified, *exposeprivatechannels* overrides the default route hint
logic, which will use unpublished channels only if there are no
published channels. If *true* unpublished channels are always considered
as a route hint candidate; if *false*, never.  If it is a short channel id
(e.g. *1x1x3*) or array of short channel ids (or a remote alias), only those specific channels
will be considered candidates, even if they are public or dead-ends.

The route hint is selected from the set of incoming channels of which:
peer's balance minus their reserves is at least *amount\_msat*, state is
normal, the peer is connected and not a dead end (i.e. has at least one
other public channel). The selection uses some randomness to prevent
probing, but favors channels that become more balanced after the
payment.

If specified, *cltv* sets the *min\_final\_cltv\_expiry* for the invoice.
Otherwise, it's set to the parameter **cltv-final**.

If *deschashonly* is true (default false), then the bolt11 returned
contains a hash of the *description*, rather than the *description*
itself: this allows much longer descriptions, but they must be
communicated via some other mechanism.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **bolt11** (string): the bolt11 string
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment
- **payment\_secret** (secret): the *payment\_secret* to place in the onion
- **expires\_at** (u64): UNIX timestamp of when invoice expires
- **created\_index** (u64): 1-based index indicating order this invoice was created in *(added v23.08)*

The following warnings may also be returned:

- **warning\_capacity**: even using all possible channels, there's not enough incoming capacity to pay this invoice.
- **warning\_offline**: there would be enough incoming capacity, but some channels are offline, so there isn't.
- **warning\_deadends**: there would be enough incoming capacity, but some channels are dead-ends (no other public channels from those peers), so there isn't.
- **warning\_private\_unused**: there would be enough incoming capacity, but some channels are unannounced and *exposeprivatechannels* is *false*, so there isn't.
- **warning\_mpp**: there is sufficient capacity, but not in a single channel, so the payer will have to use multi-part payments.

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, an error is returned and no invoice is created. If the
lightning process fails before responding, the caller should use
lightning-listinvoices(7) to query whether this invoice was created or
not.

The following error codes may occur:

- -1: Catchall nonspecific error.
- 900: An invoice with the given *label* already exists.
- 901: An invoice with the given *preimage* already exists.
- 902: None of the specified *exposeprivatechannels* were usable.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoices(7), lightning-delinvoice(7), lightning-pay(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:ffe488e123bad4592e4083c5eaaad0c01194d6ecc9fe14ce9a6ffd488aae8129)
