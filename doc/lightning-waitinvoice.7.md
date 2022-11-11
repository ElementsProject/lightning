lightning-waitinvoice -- Command for waiting for specific payment
=================================================================

SYNOPSIS
--------

**waitinvoice** *label*

DESCRIPTION
-----------

The **waitinvoice** RPC command waits until a specific invoice is paid,
then returns that single entry as per **listinvoice**.

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

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: If the invoice is deleted while unpaid, or the invoice does not exist.
- 903: If the invoice expires before being paid, or is already expired.

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly
responsible.

SEE ALSO
--------

lightning-waitanyinvoice(7), lightning-listinvoice(7),
lightning-delinvoice(7), lightning-invoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:bd853f0a27258e0e3780c0dd6cdd8fca7ba8d95a00d247704ed3f3f55c2f086e)
