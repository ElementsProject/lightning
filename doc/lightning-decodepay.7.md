lightning-decodepay -- Command for decoding a bolt11 string (low-level)
=======================================================================

SYNOPSIS
--------

**decodepay** *bolt11* \[*description*\]

DESCRIPTION
-----------

The **decodepay** RPC command checks and parses a *bolt11* string as
specified by the BOLT 11 specification.

RETURN VALUE
------------

On success, an object is returned with the following fields, as
specified by BOLT11:
-   *currency*: the BIP173 name for the currency.
-   *timestamp*: the UNIX-style timestamp of the invoice.
-   *expiry*: the number of seconds this is valid after *timestamp*.
-   *payee*: the public key of the recipient.
-   *payment\_hash*: the payment hash of the request.
-   *signature*: the DER-encoded signature.
-   *description*: the description of the purpose of the purchase (see
    below)

The following fields are optional:
-   *msatoshi*: the number of millisatoshi requested (if any).
-   *amount\_msat*: the same as above, with *msat* appended (if any).
-   *fallbacks*: array of fallback address object containing a *hex*
    string, and both *type* and *addr* if it is recognized as one of
    *P2PKH*, *P2SH*, *P2WPKH*, or *P2WSH*.
-   *routes*: an array of routes. Each route is an arrays of objects,
    each containing *pubkey*, *short\_channel\_id*, *fee\_base\_msat*,
    *fee\_proportional\_millionths* and *cltv\_expiry\_delta*.
-   *extra*: an array of objects representing unknown fields, each with
    one-character *tag* and a *data* bech32 string.

Technically, the *description* field is optional if a
*description\_hash* field is given, but in this case **decodepay** will
only succeed if the optional *description* field is passed and matches
the *description\_hash*. In practice, these are currently unused.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-pay(7), lightning-getroute(7), lightning-sendpay(7).

[BOLT
\#11](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

