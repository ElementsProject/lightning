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

[comment]: # ( SHA256STAMP:8e732382fa499ed98dc015a1525b4fa07a2d20d5009c305945f06dae84b408c7)
