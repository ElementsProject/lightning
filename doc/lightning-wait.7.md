lightning-wait -- Command to wait for creations, changes and deletions
======================================================================

SYNOPSIS
--------

**wait** *subsystem* *indexname* *nextvalue* 

DESCRIPTION
-----------

Command *added* in v23.08.

The **wait** RPC command returns once the index given by *indexname* in *subsystem* reaches or exceeds *nextvalue*. All indexes start at 0, when no events have happened (**wait** with a *nextvalue* of 0 is a way of getting the current index, though naturally this is racy!).

- **subsystem** (string) (one of "invoices", "forwards", "sendpays"): The subsystem to get the next index value from.
   `invoices`: corresponding to `listinvoices` (added in *v23.08*).
   `sendpays`: corresponding to `listsendpays` (added in *v23.11*).
   `forwards`: corresponding to `listforwards` (added in *v23.11*).
- **indexname** (string) (one of "created", "updated", "deleted"): The name of the index to get the next value for.
   `created` is incremented by one for every new object.
   `updated` is incremented by one every time an object is changed.
   `deleted` is incremented by one every time an object is deleted.
- **nextvalue** (u64): The next value of the index.

RELIABILITY
-----------

Indices can go forward by more than one; in particlar, if multiple objects were created and the one deleted, you could see this effect. Similarly, there are some places (e.g. invoice expiration) where we can update multiple entries at once.

Indices only monotoncally increase.

USAGE
-----

The **wait** RPC is used to track changes in the system. Consider tracking invoices being paid or expiring. The simplest (and inefficient method) would be:
1. Call `listinvoices` to get the current state of all invoices, and remember the highest `updated_index`. Say it was 5.
2. Call `wait invoices updated 6`.
3. When it returns, call `listinvoices` again to see what changed.

This is obviously inefficient, so there are two optimizations:
1. Call `listinvoices` with `index=updated` and `start=6` to only see invoices with `updated_index` greater than or equal to 6.
2. `wait` itself may also return some limited subset of fields from the list command (it can't do this in all cases); for `invoices` this is `label` and `status`, allowing many callers to avoid the `listinvoices` call.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:wait#1",
  "method": "wait",
  "params": {
    "subsystem": "invoices",
    "indexname": "created",
    "nextvalue": 1
  }
}
{
  "id": "example:wait#2",
  "method": "wait",
  "params": {
    "subsystem": "invoices",
    "indexname": "updated",
    "nextvalue": 2
  }
}
{
  "id": "example:wait#3",
  "method": "wait",
  "params": {
    "subsystem": "sendpays",
    "indexname": "updated",
    "nextvalue": 2
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **subsystem** (string) (one of "invoices", "forwards", "sendpays")
- **created** (u64, optional): 1-based index indicating order entry was created.
- **updated** (u64, optional): 1-based index indicating order entry was updated.
- **deleted** (u64, optional): 1-based index indicating order entry was deleted.

If **subsystem** is "invoices":
  - **details** (object, optional):
    - **status** (string, optional) (one of "unpaid", "paid", "expired"): Whether it's paid, unpaid or unpayable.
    - **label** (string, optional): Unique label supplied at invoice creation.
    - **description** (string, optional): Description used in the invoice.
    - **bolt11** (string, optional): The BOLT11 string.
    - **bolt12** (string, optional): The BOLT12 string.

If **subsystem** is "forwards":
  - **details** (object, optional):
    - **status** (string, optional) (one of "offered", "settled", "failed", "local\_failed"): Still ongoing, completed, failed locally, or failed after forwarding.
    - **in\_channel** (short\_channel\_id, optional): Unique label supplied at invoice creation.
    - **in\_htlc\_id** (u64, optional): The unique HTLC id the sender gave this (not present if incoming channel was closed before upgrade to v22.11).
    - **in\_msat** (msat, optional): The value of the incoming HTLC.
    - **out\_channel** (short\_channel\_id, optional): The channel that the HTLC (trying to) forward to.

If **subsystem** is "sendpays":
  - **details** (object, optional):
    - **status** (string, optional) (one of "pending", "failed", "complete"): Status of the payment.
    - **partid** (u64, optional): Part number (for multiple parts to a single payment).
    - **groupid** (u64, optional): Grouping key to disambiguate multiple attempts to pay an invoice or the same payment\_hash.
    - **payment\_hash** (hash, optional): The hash of the *payment\_preimage* which will prove payment.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "subsystem": "invoices",
  "created": 1,
  "details": {
    "status": "unpaid",
    "label": "invlabel",
    "bolt11": "lnbcrt420p1pjmxtevsp5d8c6gnaj8lyjy2qly783vklda9dfaqeyzyc37agxxp8h3uguv8pqpp5w6lhwxhqnuew4hle5h7qwjm27zz784mvsrzhmayhscy5t2hy5c4qdqvd9h8ver9wd3sxqyjw5qcqp99qxpqysgq09gxhjhwu9u3z6dlt5ln5f4g8zl78wz4pgh0am3kz54m9lllhqckf4gmhmt2ftrclq5x62zkqmggc7y0ju0ghdfwjz8hyd8l5cqvemgpyyhm6w"
  }
}
{
  "subsystem": "invoices",
  "updated": 2,
  "details": {
    "status": "expired"
  }
}
{
  "subsystem": "sendpays",
  "updated": 2,
  "details": {
    "status": "complete",
    "partid": 0,
    "groupid": 1,
    "payment_hash": "220dcfcf43e1fab3ce30f70eb943c3ce962393f5a65ced52d749e324b443d19e"
  }
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listinvoice(7), lightning-listforwards(7), lightning-listsendpays(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
