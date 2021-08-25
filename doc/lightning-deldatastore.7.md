lightning-deldatastore -- Command for removing (plugin) data
============================================================

SYNOPSIS
--------

**deldatastore** *key*

DESCRIPTION
-----------

The **deldatastore** RPC command allows plugins to delete data it has
stored in the c-lightning database.

The command fails if the *key* isn't present.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **key** (string): The key which has been removed from the datastore
- **hex** (hex): The hex data which has removed from the datastore
- **string** (string, optional): The data as a string, if it's valid utf-8
[comment]: # (GENERATE-FROM-SCHEMA-END)

The main cause of failure is an non-existing entry.

The following error codes may occur:
- -32602: invalid parameters, including non-existing key.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listdatastore(7), lightning-datastore(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:cc1dedfded4902f59879665e95a1a877c8c72c0e217a3db3de3ae8dde859e67a)
