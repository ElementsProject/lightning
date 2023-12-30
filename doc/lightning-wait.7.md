lightning-wait -- Command to wait for creations, changes and deletions
======================================================================

SYNOPSIS
--------

**wait** *subsystem* *indexname* *nextvalue*

DESCRIPTION
-----------

The **wait** RPC command returns once the index given by *indexname*
in *subsystem* reaches or exceeds *nextvalue*.  All indexes start at 0, when no
events have happened (**wait** with a *nextvalue* of 0 is a way of getting
the current index, though naturally this is racy!).

*indexname* is one of `created`, `updated` or `deleted`:

- `created` is incremented by one for every new object.
- `updated` is incremented by one every time an object is changed.
- `deleted` is incremented by one every time an object is deleted.

*subsystem* is one of:

- `invoices`: corresponding to `listinvoices` (added in *v23.08*)
- `sendpays`: corresponding to `listsendpays` (added in *v23.11*)
- `forwards`: corresponding to `listforwards` (added in *v23.11*)


RELIABILITY
-----------

Indices can go forward by more than one; in particlar, if multiple
objects were created and the one deleted, you could see this effect.
Similarly, there are some places (e.g. invoice expiration) where we
can update multiple entries at once.

Indices only monotoncally increase.

USAGE
-----

The **wait** RPC is used to track changes in the system.  Consider
tracking invoices being paid or expiring.  The simplest (and
inefficient method) would be:

1. Call `listinvoices` to get the current state of all invoices, and
   remember the highest `updated_index`.  Say it was 5.
2. Call `wait invoices updated 6`.
3. When it returns, call `listinvoices` again to see what changed.

This is obviously inefficient, so there are two optimizations:

1. Call `listinvoices` with `index=updated` and `start=6` to only see invoices
   with `updated_index` greater than or equal to 6.
2. `wait` itself may also return some limited subset of fields from the list
   command (it can't do this in all cases); for `invoices` this is `label`
   and `status`, allowing many callers to avoid the `listinvoices` call.

RETURN VALUE
------------
[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **subsystem** (string) (one of "invoices", "forwards", "sendpays")
- **created** (u64, optional): 1-based index indicating order entry was created
- **updated** (u64, optional): 1-based index indicating order entry was updated
- **deleted** (u64, optional): 1-based index indicating order entry was deleted

If **subsystem** is "invoices":

  - **details** (object, optional):
    - **status** (string, optional): Whether it's paid, unpaid or unpayable (one of "unpaid", "paid", "expired")
    - **label** (string, optional): unique label supplied at invoice creation
    - **description** (string, optional): description used in the invoice
    - **bolt11** (string, optional): the BOLT11 string
    - **bolt12** (string, optional): the BOLT12 string

If **subsystem** is "forwards":

  - **details** (object, optional):
    - **status** (string, optional): still ongoing, completed, failed locally, or failed after forwarding (one of "offered", "settled", "failed", "local\_failed")
    - **in\_channel** (short\_channel\_id, optional): unique label supplied at invoice creation
    - **in\_htlc\_id** (u64, optional): the unique HTLC id the sender gave this (not present if incoming channel was closed before upgrade to v22.11)
    - **in\_msat** (msat, optional): the value of the incoming HTLC
    - **out\_channel** (short\_channel\_id, optional): the channel that the HTLC (trying to) forward to

If **subsystem** is "sendpays":

  - **details** (object, optional):
    - **status** (string, optional): status of the payment (one of "pending", "failed", "complete")
    - **partid** (u64, optional): Part number (for multiple parts to a single payment)
    - **groupid** (u64, optional): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment\_hash
    - **payment\_hash** (hash, optional): the hash of the *payment\_preimage* which will prove payment

[comment]: # (GENERATE-FROM-SCHEMA-END)

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly
responsible.

SEE ALSO
--------

lightning-listinvoice(7), lightning-listforwards(7), lightning-listsendpays(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:a6686d2d46b49984c3848305dc15129a7436dd48d95f6afd9ba0e2902b52fc5d)
