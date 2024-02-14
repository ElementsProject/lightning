lightning-delforward -- Command for removing a forwarding entry
===============================================================

SYNOPSIS
--------

**delforward** *in\_channel* *in\_htlc\_id* *status* 

DESCRIPTION
-----------

The **delforward** RPC command removes a single forward from **listforwards**, using the uniquely-identifying *in\_channel* and *in\_htlc\_id* (and, as a sanity check, the *status*) given by that command.

This command is mainly used by the *autoclean* plugin (see lightningd- config(7)), As these database entries are only kept for your own analysis, removing them has no effect on the running of your node.

- **in\_channel** (short\_channel\_id): Only the matching forwards on the given inbound channel are deleted. Note: for **listforwards** entries without an *in\_htlc\_id* entry (no longer created in v22.11, but can exist from older versions), a value of 18446744073709551615 can be used, but then it will delete *all* entries without *in\_htlc\_id* for this *in\_channel* and *status*.
- **in\_htlc\_id** (u64): The unique HTLC id the sender gave this (not present if incoming channel was closed before upgrade to v22.11).
- **status** (string) (one of "settled", "local\_failed", "failed"): The status of the forward to delete. You cannot delete forwards which have status *offered* (i.e. are currently active).

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:delforward#1",
  "method": "delforward",
  "params": {
    "in_channel": "103x1x0",
    "in_htlc_id": 2,
    "status": "local_failed"
  }
}
{
  "id": "example:delforward#2",
  "method": "delforward",
  "params": [
    "103x1x0",
    1,
    "failed"
  ]
}
```

RETURN VALUE
------------

On success, an empty object is returned.

EXAMPLE JSON RESPONSE
---------------------

```json
{}
{}
```

ERRORS
------

The following errors may be reported:

- 1401: The forward specified does not exist.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-autoclean(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
