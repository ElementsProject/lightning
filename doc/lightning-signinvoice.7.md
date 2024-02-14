lightning-signinvoice -- Low-level invoice signing
==================================================

SYNOPSIS
--------

**signinvoice** *invstring* 

DESCRIPTION
-----------

Command *added* in v23.02.

The **signinvoice** RPC command signs an invoice. Unlike **createinvoice** it does not save the invoice into the database and thus does not require the preimage.

- **invstring** (string): Bolt11 form, but the final signature is ignored. Minimal sanity checks are done.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:signinvoice#1",
  "method": "signinvoice",
  "params": [
    "lnbcrt10n1pjmxt3lsp5jumuz2sv3ca68kzd92hp3wdtpx8ghnxur65fs6maw6dyxsleqd0spp5nadvvh7uzk2qzh8d9d7tsxr08l9uaz2vjeuuahqtufjv52d0eassdq8d9h8vvgxqyjw5qcqp99qxpqysgq4rrn702eum6c9ld9khlz39vdyd8zcwrav5ygqvu6w54aep6yarkyfrnk990yf5prpasgzmj52stektf6mzwdl5hc6qlsglt2a0pwp0spwww44w"
  ]
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **bolt11** (string): The bolt11 string.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "bolt11": "lnbcrt10n1pjmxt3lsp5jumuz2sv3ca68kzd92hp3wdtpx8ghnxur65fs6maw6dyxsleqd0spp5nadvvh7uzk2qzh8d9d7tsxr08l9uaz2vjeuuahqtufjv52d0eassdq8d9h8vvgxqyjw5qcqp99qxpqysgq3nhrd72qe7wmc2hvwhaqnx05y6dzxh2tal02kw055er7uutkkrcreccm37ce6wv7ee8q70ktlr9fy3fd635hc2k98a4svd9c8v4cpjsppm2eee"
}
```

ERRORS
------

The following error codes may occur:

- -1: Catchall nonspecific error.

AUTHOR
------

Carl Dong <<contact@carldong.me>> is mainly responsible.

SEE ALSO
--------

lightning-createinvoice(7), lightning-invoice(7), lightning-listinvoices(7), lightning-delinvoice(7), lightning-getroute(7), lightning-sendpay(7), lightning-offer(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
