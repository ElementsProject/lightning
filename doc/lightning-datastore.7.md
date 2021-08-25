lightning-datastore -- Command for storing (plugin) data
========================================================

SYNOPSIS
--------

**datastore** *key* [*string*|*hex*]

DESCRIPTION
-----------

The **datastore** RPC command allows plugins to store data in the
c-lightning database, for later retrieval.

There can only be one entry for each *key*, so prefixing with the
plugin name (e.g. `summary.`) is recommended.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **key** (string): The key which has been added to the datastore
- **hex** (hex): The hex data which has been added to the datastore
- **string** (string, optional): The data as a string, if it's valid utf-8
[comment]: # (GENERATE-FROM-SCHEMA-END)

The main cause of failure is an already-existing entry.

The following error codes may occur:
- -32602: invalid parameters, including already-existing key.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listdatastore(7), lightning-deldatastore(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:5eda4592b0a5e893853ea15ce7e800bb94e3a26ebd932507c2a55890f56fee14)
