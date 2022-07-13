lightning-listdatastore -- Command for listing (plugin) data
============================================================

SYNOPSIS
--------

**listdatastore** [*key*]

DESCRIPTION
-----------

The **listdatastore** RPC command allows plugins to fetch data which was
stored in the Core Lightning database.

All immediate children of the *key* (or root children) are returned:
a *key* with children won't have a *hex* or *generation* entry.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **datastore** is returned.  It is an array of objects, where each object contains:
- **key** (array of strings):
  - Part of the key added to the datastore
- **generation** (u64, optional): The number of times this has been updated
- **hex** (hex, optional): The hex data from the datastore
- **string** (string, optional): The data as a string, if it's valid utf-8

[comment]: # (GENERATE-FROM-SCHEMA-END)

The following error codes may occur:
- -32602: invalid parameters.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-datastore(7), lightning-deldatastore(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:6c6f4c08a88b2a8c8cdc4c36783da86d8e8de0d5ee39261f3304e0eb41f0eb41)
