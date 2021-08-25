lightning-listdatastore -- Command for listing (plugin) data
============================================================

SYNOPSIS
--------

**listdatastore** [*key*]

DESCRIPTION
-----------

The **listdatastore** RPC command allows plugins to fetch data which was
stored in the c-lightning database.

All entries are returned in *key* isn't present; if *key* is present,
zero or one entries are returned.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **datastore** is returned.  It is an array of objects, where each object contains:
- **key** (string): The key which from the datastore
- **hex** (hex): The hex data from the datastore
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

[comment]: # ( SHA256STAMP:b93d725952e9ac5134dc25711d9bfbbd8b719e8ee8592f27bd1becbb56f89971)
