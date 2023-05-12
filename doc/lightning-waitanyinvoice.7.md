lightning-waitanyinvoice -- Command for waiting for payments
============================================================

SYNOPSIS
--------

**waitanyinvoice** [*lastpay\_index*] [*timeout*]

DESCRIPTION
-----------

The **waitanyinvoice** RPC command waits until an invoice is paid, then
returns a single entry as per **listinvoice**. It will not return for
any invoices paid prior to or including the *lastpay\_index*.

This is usually called iteratively: once with no arguments, then
repeatedly with the returned *pay\_index* entry. This ensures that no
paid invoice is missed.

The *pay\_index* is a monotonically-increasing number assigned to an
invoice when it gets paid. The first valid *pay\_index* is 1; specifying
*lastpay\_index* of 0 equivalent to not specifying a *lastpay\_index*.
Negative *lastpay\_index* is invalid.

If *timeout* is specified, wait at most that number of seconds, which
must be an integer.
If the specified *timeout* is reached, this command will return with an
error.
You can specify this to 0 so that **waitanyinvoice** will return
immediately with an error if no pending invoice is available yet.
If unspecified, this command will wait indefinitely.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **label** (string): unique label supplied at invoice creation
- **description** (string): description used in the invoice
- **payment\_hash** (hash): the hash of the *payment\_preimage* which will prove payment (always 64 characters)
- **status** (string): Whether it's paid or expired (one of "paid", "expired")
- **expires\_at** (u64): UNIX timestamp of when it will become / became unpayable
- **amount\_msat** (msat, optional): the amount required to pay this invoice
- **bolt11** (string, optional): the BOLT11 string (always present unless *bolt12* is)
- **bolt12** (string, optional): the BOLT12 string (always present unless *bolt11* is)

If **status** is "paid":

  - **pay\_index** (u64): Unique incrementing index for this payment
  - **amount\_received\_msat** (msat): the amount actually received (could be slightly greater than *amount\_msat*, since clients may overpay)
  - **paid\_at** (u64): UNIX timestamp of when it was paid
  - **payment\_preimage** (secret): proof of payment (always 64 characters)

[comment]: # (GENERATE-FROM-SCHEMA-END)

Possible errors are:

* 904.
  The *timeout* was reached without an invoice being paid.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-waitinvoice(7), lightning-listinvoice(7),
lightning-delinvoice(7), lightning-invoice(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:bd853f0a27258e0e3780c0dd6cdd8fca7ba8d95a00d247704ed3f3f55c2f086e)
