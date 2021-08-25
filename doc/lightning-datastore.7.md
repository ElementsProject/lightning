lightning-datastore -- Command for storing (plugin) data
========================================================

SYNOPSIS
--------

**datastore** *key* [*string*] [*hex*] [*mode*] [*generation*]

DESCRIPTION
-----------

The **datastore** RPC command allows plugins to store data in the
c-lightning database, for later retrieval.

There can only be one entry for each *key*, so prefixing with the
plugin name (e.g. `summary.`) is recommended.

*mode* is one of "must-create" (default, fails it it already exists),
"must-replace" (fails it it doesn't already exist),
"create-or-replace" (never fails), "must-append" (must already exist,
append this to what's already there) or "create-or-append" (append if
anything is there, otherwise create).

*generation*, if specified, means that the update will fail if the
previously-existing data is not exactly that generation.  This allows
for simple atomicity.  This is only legal with *mode* "must-replace"
or "must-append".

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **key** (string): The key which has been added to the datastore
- **generation** (u64): The number of times this has been updated
- **hex** (hex): The hex data which has been added to the datastore
- **string** (string, optional): The data as a string, if it's valid utf-8
[comment]: # (GENERATE-FROM-SCHEMA-END)

The following error codes may occur:
- 1202: The key already exists (and mode said it must not)
- 1203: The key does not exist (and mode said it must)
- 1204: The generation was wrong (and generation was specified)
- -32602: invalid parameters

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listdatastore(7), lightning-deldatastore(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:0867f9910b75ef66e640a92aad55dbab7ce0b3278fd1fb200f91c2a1a6164409)
