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

ERRORS
------

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

[comment]: # ( SHA256STAMP:1ca3d3b2f0ec5ef0a1dd702e6ce0c17125f8c9bbd3d91d73243b38eb9c4ad84e)
