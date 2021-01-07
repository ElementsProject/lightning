lightning-offerout -- Command for offering payments
=================================================

SYNOPSIS
--------

*EXPERIMENTAL_FEATURES only*

**offerout** *amount* *description* \[*vendor*\] \[*label*\] \[*absolute_expiry*\] \[*refund_for*\]

DESCRIPTION
-----------

The **offerout** RPC command creates an offer, which is a request to
send an invoice for us to pay (technically, this is referred to as a
`send_invoice` offer to distinguish a normal lightningd-offer(7)
offer).  It automatically enables the accepting and payment of
corresponding invoice message (we will only pay once, however!).

The *amount* parameter can be the string "any", which creates an offer
that can be paid with any amount (e.g. a donation).  Otherwise it can
be a positive value in millisatoshi precision; it can be a whole
number, or a whole number ending in *msat* or *sat*, or a number with
three decimal places ending in *sat*, or a number with 1 to 11 decimal
places ending in *btc*.

The *description* is a short description of purpose of the offer,
e.g. *withdrawl from ATM*. This value is encoded into the resulting offer and is
viewable by anyone you expose this offer to. It must be UTF-8, and
cannot use *\\u* JSON escape codes.

The *vendor* is another (optional) field exposed in the offer, and
reflects who is issuing this offer (i.e. you) if appropriate.

The *label* field is an internal-use name for the offer, which can
be any UTF-8 string.

The *absolute_expiry* is optionally the time the offer is valid until,
in seconds since the first day of 1970 UTC.  If not set, the offer
remains valid (though it can be deactivated by the issuer of course).
This is encoded in the offer.

*refund_for* is a previous (paid) invoice of ours.  The
payment_preimage of this is encoded in the offer, and redemption
requires that the invoice we receive contains a valid signature using
that previous `payer_key`.

RETURN VALUE
------------

On success, an object as follows is returned:

* *offer_id*: the hash of the offer.
* *active*: true
* *single_use*: true
* *bolt12*: the bolt12 offer, starting with "lno1"

Optionally:
* *label*: the user-specified label.

On failure, an error is returned and no offer is created. If the
lightning process fails before responding, the caller should use
lightning-listoffers(7) to query whether this offer was created or
not.

The following error codes may occur:
- -1: Catchall nonspecific error.
- 1000: Offer with this offer_id already exists.

NOTES
-----

The specification allows quantity, recurrence and alternate currencies on
offers which contain `send_invoice`, but these are not implemented here.

We could also allow multi-use offers, but usually you're only offering to
send money once.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-offer(7), lightning-listoffers(7), lightning-deloffer(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

