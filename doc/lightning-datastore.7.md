lightning-datastore -- Command for storing (plugin) data
========================================================

SYNOPSIS
--------

**datastore** *key* [*string*] [*hex*] [*mode*] [*generation*]

DESCRIPTION
-----------

The **datastore** RPC command allows plugins to store data in the
Core Lightning database, for later retrieval.

*key* is an array of values (though a single value is treated as a
one-element array), to form a hierarchy.  Using the first element of
the key as the plugin name (e.g. `[ "summary" ]`) is recommended.
A key can either have children or a value, never both: parents are
created and removed automatically.

*mode* is one of "must-create" (default, fails if it already exists),
"must-replace" (fails if it doesn't already exist),
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

- **key** (array of strings):
  - Part of the key added to the datastore
- **generation** (u64, optional): The number of times this has been updated
- **hex** (hex, optional): The hex data which has been added to the datastore
- **string** (string, optional): The data as a string, if it's valid utf-8

[comment]: # (GENERATE-FROM-SCHEMA-END)

The following error codes may occur:

- 1202: The key already exists (and mode said it must not)
- 1203: The key does not exist (and mode said it must)
- 1204: The generation was wrong (and generation was specified)
- 1205: The key has children already.
- 1206: One of the parents already exists with a value.
- -32602: invalid parameters

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listdatastore(7), lightning-deldatastore(7), lightning-datastoreusage(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:098e407da175f50d8c5e9c70d61b7e9e586f74ad395a9e86532641e106eb2d60)
