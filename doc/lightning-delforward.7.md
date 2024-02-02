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

[comment]: # ( SHA256STAMP:3faddc7dd03a73725f4a3e7249c7a417a11c6ac31f8666a9df2a8e5ebcfe2875)
