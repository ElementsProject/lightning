lightning-invoice -- Command for accepting payments
===================================================

SYNOPSIS
--------

**invoice** *amount\_msat* *label* *description* [*expiry*] [*fallbacks*] [*preimage*] [*exposeprivatechannels*] [*cltv*] [*deschashonly*] 

DESCRIPTION
-----------

The **invoice** RPC command creates the expectation of a payment of a given amount of milli-satoshi: it returns a unique token which another lightning daemon can use to pay this invoice. This token includes a *route hint* description of an incoming channel with capacity to pay the invoice, if any exists.

- **amount\_msat** (msat\_or\_any): The string `any`, which creates an invoice that can be paid with any amount. Otherwise it is a positive value in millisatoshi precision; it can be a whole number, or a whole number ending in *msat* or *sat*, or a number with three decimal places ending in *sat*, or a number with 1 to 11 decimal places ending in *btc*.
- **label** (one of): A unique string or number (which is treated as a string, so `01` is different from `1`); it is never revealed to other nodes on the lightning network, but it can be used to query the status of this invoice.:
  - (string)
  - (integer)
- **description** (string): A short description of purpose of payment, e.g. *1 cup of coffee*. This value is encoded into the BOLT11 invoice and is viewable by any node you send this invoice to (unless *deschashonly* is true as described below). It must be UTF-8, and cannot use *\u* JSON escape codes.
- **expiry** (u64, optional): The time the invoice is valid for, in seconds. If no value is provided the default of 604800 (1 week) is used.
- **fallbacks** (array of strings, optional): One or more fallback addresses to include in the invoice (in order from most- preferred to least): note that these arrays are not currently tracked to fulfill the invoice.:
  - (string, optional)
- **preimage** (hex, optional): A 64-digit hex string to be used as payment preimage for the created invoice. By default, if unspecified, lightningd will generate a secure pseudorandom preimage seeded from an appropriate entropy source on your system. **IMPORTANT**: if you specify the *preimage*, you are responsible, to ensure appropriate care for generating using a secure pseudorandom generator seeded with sufficient entropy, and keeping the preimage secret. This parameter is an advanced feature intended for use with cutting-edge cryptographic protocols and should not be used unless explicitly needed.
- **exposeprivatechannels** (one of, optional): If specified, it overrides the default route hint logic, which will use unpublished channels only if there are no published channels.:
  - (boolean): If *True* unpublished channels are always considered as a route hint candidate; if *False*, never.
  - (array of short\_channel\_ids): Array of short channel ids (or a remote alias), only those specific channels will be considered candidates, even if they are public or dead-ends.
    - (short\_channel\_id, optional)
  - (short\_channel\_id): If it is a short channel id (e.g. *1x1x3*), only this specific channel will be considered candidate, even if it is public or dead-end.
- **cltv** (u32, optional): If specified, sets the *min\_final\_cltv\_expiry* for the invoice. Otherwise, it's set to the parameter **cltv-final**.
- **deschashonly** (boolean, optional): If True, then the bolt11 returned contains a hash of the *description*, rather than the *description* itself: this allows much longer descriptions, but they must be communicated via some other mechanism. The default is False.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:invoice#1",
  "method": "invoice",
  "params": {
    "amount_msat": 11000000,
    "label": "xEoCR94SIz6UIRUEkxum",
    "description": [
      "XEoCR94SIz6UIRUEkxum."
    ],
    "expiry": null,
    "fallbacks": null,
    "preimage": null,
    "exposeprivatechannels": null,
    "cltv": null,
    "deschashonly": null
  }
}
{
  "id": "example:invoice#2",
  "method": "invoice",
  "params": {
    "amount_msat": 100,
    "label": "8",
    "description": "inv",
    "expiry": null,
    "fallbacks": null,
    "preimage": null,
    "exposeprivatechannels": null,
    "cltv": null,
    "deschashonly": null
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **bolt11** (string): The bolt11 string.
- **payment\_hash** (hash): The hash of the *payment\_preimage* which will prove payment.
- **payment\_secret** (secret): The *payment\_secret* to place in the onion.
- **expires\_at** (u64): UNIX timestamp of when invoice expires.
- **created\_index** (u64): 1-based index indicating order this invoice was created in. *(added v23.08)*

The following warnings may also be returned:

- **warning\_capacity**: Even using all possible channels, there's not enough incoming capacity to pay this invoice.
- **warning\_offline**: There would be enough incoming capacity, but some channels are offline, so there isn't.
- **warning\_deadends**: There would be enough incoming capacity, but some channels are dead-ends (no other public channels from those peers), so there isn't.
- **warning\_private\_unused**: There would be enough incoming capacity, but some channels are unannounced and *exposeprivatechannels* is *false*, so there isn't.
- **warning\_mpp**: There is sufficient capacity, but not in a single channel, so the payer will have to use multi-part payments.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "payment_hash": "072b1d20f4a7c757a56d5fb10eaed40b58b68849da41fe396cdbd2d81692875a",
  "expires_at": 1706757730,
  "bolt11": "lnbcrt110u1pjmr5lzsp5sfjyj3xn7ux592k36hmmt4ax98n6lgct22wvj54yck0upcmep63qpp5qu436g855lr40ftdt7csatk5pdvtdzzfmfqluwtvm0fds95jsadqdpq0pzk7s6j8y69xjt6xe25j5j4g44hsatdxqyjw5qcqp99qxpqysgquwma3zrw4cd8e8j4u9uh4gxukaacckse64kx2l9dqv8rvrysdq5r5dt38t9snqj9u5ar07h2exr4fg56wpudkhkk7gtxlyt72ku5fpqqd4fnlk",
  "payment_secret": "82644944d3f70d42aad1d5f7b5d7a629e7afa30b529cc952a4c59fc0e3790ea2",
  "created_index": 1,
  "warning_deadends": "Insufficient incoming capacity, once dead-end peers were excluded"
}
{
  "payment_hash": "f59ae0204dfe8e913207ea36646255b9d2c7c8229e8693d30547fc622eddb6b4",
  "expires_at": 1709229182,
  "bolt11": "lnbcrt1n1pja0z07sp5n8fk890nrq7zlcue0lgu7cduaaz765u5rg0kcud4amphuppu8wxspp57kdwqgzdl68fzvs8agmxgcj4h8fv0jpzn6rf85c9gl7xytkak66qdq9d9h8vxqyjw5qcqp99qxpqysgqrneaxh0plvjft457yv3q92rak57a6xw33m6phr0mrsy69sudzgez3adkzdsgwzy32z5usjpxm4rjgcg70h047wf0pgc4l9gyaj2h9ssqcrtv32",
  "payment_secret": "99d36395f3183c2fe3997fd1cf61bcef45ed53941a1f6c71b5eec37e043c3b8d",
  "created_index": 9,
  "warning_capacity": "Insufficient incoming channel capacity to pay invoice"
}
```

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

lightning-listinvoices(7), lightning-delinvoice(7), lightning-pay(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
