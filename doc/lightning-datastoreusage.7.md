lightning-datastoreusage -- Command for listing datastore usage info
============================================================

SYNOPSIS
--------

**datastoreusage**

DESCRIPTION
-----------

The **datastoreusage** RPC command allows the caller to fetch the 
total bytes that are stored under a certain *key* (or from the root),
including the size of the *key*.

All descendants of the *key* (or root) are taken into account.
RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **datastoreusage** is returned.  It is an object containing:

- **key** (string): The key from which the database was traversed.
- **total\_bytes** (u64): The total bytes that are stored under the *key*, including the all descendants data and the size of the keys themselves.

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Peter Neuroth <<pet.v.ne@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-datastore(7), lightning-deldatastore(7), lightning-listdatastore(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:743b3308974872f191362fcd0b1af647ea1efd28ae30ea04f6deb22418871a17)
