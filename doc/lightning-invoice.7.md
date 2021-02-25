lightning-invoice -- Command for accepting payments
===================================================

SYNOPSIS
--------

**invoice** *msatoshi* *label* *description* \[*expiry*\]
\[*fallbacks*\] \[*preimage*\] \[*exposeprivatechannels*\] \[*cltv*\]

DESCRIPTION
-----------

The **invoice** RPC command creates the expectation of a payment of a
given amount of milli-satoshi: it returns a unique token which another
lightning daemon can use to pay this invoice. This token includes a
*route hint* description of an incoming channel with capacity to pay the
invoice, if any exists.

The *msatoshi* parameter can be the string "any", which creates an
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
viewable by any node you send this invoice to. It must be UTF-8, and
cannot use *\\u* JSON escape codes.

The *expiry* is optionally the time the invoice is valid for; without a
suffix it is interpreted as seconds, otherwise suffixes *s*, *m*, *h*,
*d*, *w* indicate seconds, minutes, hours, days and weeks respectively.
If no value is provided the default of 604800 (1w) is used.

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
(e.g. *1x1x3*) or array of short channel ids, only those specific channels
will be considered candidates, even if they are public or dead-ends.

The route hint is selected from the set of incoming channels of which:
peer’s balance minus their reserves is at least *msatoshi*, state is
normal, the peer is connected and not a dead end (i.e. has at least one
other public channel). The selection uses some randomness to prevent
probing, but favors channels that become more balanced after the
payment.

If specified, *cltv* sets the *min_final_cltv_expiry* for the invoice.
Otherwise, it's set to the parameter **cltv-final**.

RETURN VALUE
------------

On success, a hash is returned as *payment\_hash* to be given to the
payer, and the *expiry\_time* as a UNIX timestamp. It also returns a
BOLT11 invoice as *bolt11* to be given to the payer.

On failure, an error is returned and no invoice is created. If the
lightning process fails before responding, the caller should use
lightning-listinvoice(7) to query whether this invoice was created or
not.

The following error codes may occur:
- -1: Catchall nonspecific error.
- 900: An invoice with the given *label* already exists.
- 901: An invoice with the given *preimage* already exists.
- 902: None of the specified *exposeprivatechannels* were usable.

One of the following warnings may occur (on success):
- *warning\_offline* if no channel with a currently connected peer has
    the incoming capacity to pay this invoice
- *warning\_capacity* if there is no channel that has sufficient
    incoming capacity
- *warning\_deadends* if there is no channel that is not a dead-end
- *warning_mpp* if there is sufficient capacity, but not in a single channel,
    so the payer will have to use multi-part payments.
- *warning_mpp_capacity* if there is not sufficient capacity, even with all
    channels.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoice(7), lightning-delinvoice(7),
lightning-getroute(7), lightning-sendpay(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

