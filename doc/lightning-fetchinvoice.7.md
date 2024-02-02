lightning-fetchinvoice -- Command for fetch an invoice for an offer
===================================================================

SYNOPSIS
--------

**(WARNING: experimental-offers only)**

**fetchinvoice** *offer* [*amount\_msat*] [*quantity*] [*recurrence\_counter*] [*recurrence\_start*] [*recurrence\_label*] [*timeout*] [*payer\_note*]

DESCRIPTION
-----------

The **fetchinvoice** RPC command contacts the issuer of an *offer* to get
an actual invoice that can be paid.  It highlights any changes between the
offer and the returned invoice.

If **fetchinvoice-noconnect** is not specified in the configuation, it
will connect to the destination in the (currently common!) case where it
cannot find a route which supports `option_onion_messages`.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **invoice** (string): The BOLT12 invoice we fetched
- **changes** (object): Summary of changes from offer:
  - **description\_appended** (string, optional): extra characters appended to the *description* field.
  - **description** (string, optional): a completely replaced *description* field
  - **vendor\_removed** (string, optional): The *vendor* from the offer, which is missing in the invoice
  - **vendor** (string, optional): a completely replaced *vendor* field
  - **amount\_msat** (msat, optional): the amount, if different from the offer amount multiplied by any *quantity* (or the offer had no amount, or was not in BTC).
- **next\_period** (object, optional): Only for recurring invoices if the next period is under the *recurrence\_limit*:
  - **counter** (u64): the index of the next period to fetchinvoice
  - **starttime** (u64): UNIX timestamp that the next period starts
  - **endtime** (u64): UNIX timestamp that the next period ends
  - **paywindow\_start** (u64): UNIX timestamp of the earliest time that the next invoice can be fetched
  - **paywindow\_end** (u64): UNIX timestamp of the latest time that the next invoice can be fetched

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The following error codes may occur:

- -1: Catchall nonspecific error.
- 1002: Offer has expired.
- 1003: Cannot find a route to the node making the offer.
- 1004: The node making the offer returned an error message.
- 1005: We timed out trying to fetch an invoice.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-sendinvoice(7), lightning-pay(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:fb90f5792c2d809ee17e8bc4c838802404a1bc2c0900516cce8393fc440fecb8)
