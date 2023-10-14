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

- `invoices`: corresponding to `listinvoices`.


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
FIXME

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly
responsible.

SEE ALSO
--------

lightning-listinvoice(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
