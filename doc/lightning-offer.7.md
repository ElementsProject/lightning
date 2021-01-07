lightning-offer -- Command for accepting payments
=================================================

SYNOPSIS
--------

*EXPERIMENTAL_FEATURES only*

**offer** *amount* *description* \[*send_invoice*\] \[*label*\] \[*vendor*\] \[*quantity_min*\] \[*quantity_max*\] \[*absolute_expiry*\] \[*recurrence*\] \[*recurrence_base*\] \[*recurrence_paywindow*\] \[*recurrence_limit*\] \[*refund_for*\] \[*single_use*\]

DESCRIPTION
-----------

The **offer** RPC command creates an offer, which is a precursor to
one or more invoices.  It automatically enables the accepting of
corresponding invoice_request or invoice messages (depending on
*send_invoice*).

The *amount* parameter can be the string "any", which creates an offer
that can be paid with any amount (e.g. a donation).  Otherwise it can
be a positive value in millisatoshi precision; it can be a whole
number, or a whole number ending in *msat* or *sat*, or a number with
three decimal places ending in *sat*, or a number with 1 to 11 decimal
places ending in *btc*.

*amount* can also have an ISO 4217 postfix (i.e. USD), in which case
currency conversion will need to be done for the invoice itself.

The *description* is a short description of purpose of the offer,
e.g. *coffee*. This value is encoded into the resulting offer and is
viewable by anyone you expose this offer to. It must be UTF-8, and
cannot use *\\u* JSON escape codes.

The *vendor* is another (optional) field exposed in the offer, and
reflects who is issuing this offer (i.e. you) if appropriate.

The *send_invoice* boolean (default false unless *single_use*) creates
an offer to send money: the user of the offer will send an invoice,
rather than an invoice_request.  This is encoded in the offer.  Note
that *recurrence* and ISO 4217 currencies are not currently
well-supported for this case!

The *label* field is an internal-use name for the offer, which can
be any UTF-8 string.

The present of *quantity_min* or *quantity_max* indicates that the
invoice can specify more than one of the items within this (inclusive)
range.  The *amount* for the invoice will need to be multiplied
accordingly.  These are encoded in the offer.

The *absolute_expiry* is optionally the time the offer is valid until,
in seconds since the first day of 1970 UTC.  If not set, the offer
remains valid (though it can be deactivated by the issuer of course).
This is encoded in the offer.

*recurrence* means that an invoice is expected at regular intervals.
The argument is a positive number followed by one of "seconds",
"minutes", "hours", "days", "weeks", "months" or "years" (variants
without the trailing "s" are also permitted).  This is encoded in the
offer.  The semantics of recurrence is fairly predictable, but fully
documented in BOLT 12.  e.g. "4weeks".

*recurrence_base* is an optional time in seconds since the first day
of 1970 UTC, optionally with a "@" prefix.  This indicates when the
first period begins; without this, the recurrence periods start from
the first invoice.  The "@" prefix means that the invoice must start
by paying the first period; otherwise it is permitted to start at any
period.  This is encoded in the offer.  e.g. "@1609459200" indicates
you must start paying on the 1st January 2021.

*recurrence_paywindow* is an optional argument of form
'-time+time\[%\]'.  The first time is the number of seconds before the
start of a period in which an invoice and payment is valid, the second
time is the number of seconds after the start of the period.  For
example *-604800+86400* means you can fetch an pay the invoice 4 weeks
before the given period starts, and up to 1 day afterwards.  The
optional *%* indicates that the amount of the invoice will be scaled
by the time remaining in the period.  If this is not specified, the
default is that payment is allowed during the current and previous
periods.  This is encoded in the offer.

*recurrence_limit* is an optional argument to indicate the maximum
period which exists.  eg. "12" means there are 13 periods, from 0 to
12 inclusive.  This is encoded in the offer.

*refund_for* is the payment_preimage of a previous (paid) invoice.
This implies *send_invoice* and *single_use*.  This is encoded in the
offer.

*single_use* (default false, unless *refund_for*) indicates that the
invoice associated with the offer is only valid once; for a
*send_invoice* offer many invoices can be accepted until one is
successfully paid (and we will only attempt to pay one at any time).
For a non-*single-use* offer, we will issue any number of invoices as
requested, until one is paid, at which time we will expire all the
other invoices for this offer and issue no more.

RETURN VALUE
------------

On success, an object as follows is returned:

* *offer_id*: the hash of the offer.
* *active*: true
* *single_use*: true if *single_use* was specified or implied.
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

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listoffers(7), lightning-deloffer(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

