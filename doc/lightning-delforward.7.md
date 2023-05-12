lightning-delforward -- Command for removing a forwarding entry
===============================================================

SYNOPSIS
--------

**delforward** *in\_channel* *in\_htlc\_id* *status*

DESCRIPTION
-----------

The **delforward** RPC command removes a single forward from **listforwards**,
using the uniquely-identifying *in\_channel* and *in\_htlc\_id* (and, as a sanity
check, the *status*) given by that command.

This command is mainly used by the *autoclean* plugin (see lightningd-config(7)),
As these database entries are only kept for your own analysis, removing them
has no effect on the running of your node.

You cannot delete forwards which have status *offered* (i.e. are
currently active).

Note: for **listforwards** entries without an *in\_htlc\_id* entry (no
longer created in v22.11, but can exist from older versions), a value
of 18446744073709551615 can be used, but then it will delete *all*
entries without *in\_htlc\_id* for this *in\_channel* and *status*.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an empty object is returned.

[comment]: # (GENERATE-FROM-SCHEMA-END)

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

[comment]: # ( SHA256STAMP:636acc798ed7ae1cd307ada4dbde424c1ed8aa514600bec9adeacd5778f4d036)
