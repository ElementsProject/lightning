lightning-offer -- Command for accepting payments
=================================================

SYNOPSIS
--------

**(WARNING: experimental-offers only)**

**offer** *amount* *description* [*issuer*] [*label*] [*quantity\_max*] [*absolute\_expiry*] [*recurrence*] [*recurrence\_base*] [*recurrence\_paywindow*] [*recurrence\_limit*] [*single\_use*] [*recurrence\_start\_any\
_period*]

DESCRIPTION
-----------

The **offer** RPC command creates an offer (or returns an existing
one), which is a precursor to creating one or more invoices.  It
automatically enables the processing of an incoming invoice\_request,
and issuing of invoices.

Note that for making an offer to *pay* someone else, see lightning-invoicerequest(7).

The *amount* parameter can be the string "any", which creates an offer
that can be paid with any amount (e.g. a donation).  Otherwise it can
be a positive value in millisatoshi precision; it can be a whole
number, or a whole number ending in *msat* or *sat*, or a number with
three decimal places ending in *sat*, or a number with 1 to 11 decimal
places ending in *btc*.

*amount* can also have an ISO 4217 postfix (i.e. USD), in which case
currency conversion will need to be done for the invoice itself.  A
plugin is needed which provides the "currencyconvert" API for this
currency, otherwise the offer creation will fail.

The *description* is a short description of purpose of the offer,
e.g. *coffee*. This value is encoded into the resulting offer and is
viewable by anyone you expose this offer to. It must be UTF-8, and
cannot use *\\u* JSON escape codes.

The *issuer* is another (optional) field exposed in the offer, and
reflects who is issuing this offer (i.e. you) if appropriate.

The *label* field is an internal-use name for the offer, which can
be any UTF-8 string.  This is *NOT* encoded in the offer not sent
to the issuer.

The presence of *quantity\_max* indicates that the
invoice can specify more than one of the items up (and including)
this maximum: 0 is a special value meaning "no maximuim".
The *amount* for the invoice will need to be multiplied
accordingly.  This is encoded in the offer.

The *absolute\_expiry* is optionally the time the offer is valid until,
in seconds since the first day of 1970 UTC.  If not set, the offer
remains valid (though it can be deactivated by the issuer of course).
This is encoded in the offer.

*recurrence* means that an invoice is expected at regular intervals.
The argument is a positive number followed by one of "seconds",
"minutes", "hours", "days", "weeks", "months" or "years" (variants
without the trailing "s" are also permitted).  This is encoded in the
offer.  The semantics of recurrence is fairly predictable, but fully
documented in BOLT 12.  e.g. "4weeks".

*recurrence\_base* is an optional time in seconds since the first day
of 1970 UTC.  This indicates when the
first period begins; without this, the recurrence periods start from
the first invoice.

*recurrence\_paywindow* is an optional argument of form
'-time+time[%]'.  The first time is the number of seconds before the
start of a period in which an invoice and payment is valid, the second
time is the number of seconds after the start of the period.  For
example *-604800+86400* means you can fetch an pay the invoice 4 weeks
before the given period starts, and up to 1 day afterwards.  The
optional *%* indicates that the amount of the invoice will be scaled
by the time remaining in the period.  If this is not specified, the
default is that payment is allowed during the current and previous
periods.  This is encoded in the offer.

*recurrence\_limit* is an optional argument to indicate the maximum
period which exists.  eg. "12" means there are 13 periods, from 0 to
12 inclusive.  This is encoded in the offer.

*single\_use* (default false) indicates that the offer is only valid
once; we may issue multiple invoices, but as soon as one is paid all other
invoices will be expired (i.e. only one person can pay this offer).

*recurrence\_start\_any\_period* (default true) means that the invoice must
start by paying during any period; otherwise it must start by paying
at the first period.  Setting this to false only makes sense if
*recurrence\_base* was provided.  This is encoded in the offer.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **offer\_id** (hash): the id of this offer (merkle hash of non-signature fields)
- **active** (boolean): whether this can still be used (always *true*)
- **single\_use** (boolean): whether this expires as soon as it's paid (reflects the *single\_use* parameter)
- **bolt12** (string): the bolt12 encoding of the offer
- **used** (boolean): True if an associated invoice has been paid
- **created** (boolean): false if the offer already existed
- **label** (string, optional): the (optional) user-specified label

[comment]: # (GENERATE-FROM-SCHEMA-END)

On failure, an error is returned and no offer is created. If the
lightning process fails before responding, the caller should use
lightning-listoffers(7) to query whether this offer was created or
not.

If the offer already existed, and is still active, that is returned;
if it's not active then this call fails.

The following error codes may occur:

- -1: Catchall nonspecific error.
- 1000: Offer with this offer\_id already exists (but is not active).

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listoffers(7), lightning-disableoffer(7), lightning-invoicerequest(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:9938c16e54f86deabe03d86788600f87dffc54492ea4896d4f590916683afb0a)
