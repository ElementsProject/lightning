lightning-deldatastore -- Command for removing (plugin) data
============================================================

SYNOPSIS
--------

**deldatastore** *key* [*generation*]

DESCRIPTION
-----------

The **deldatastore** RPC command allows plugins to delete data it has
stored in the Core Lightning database.

The command fails if the *key* isn't present, or if *generation*
is specified and the generation of the data does not exactly match.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **key** (array of strings):
  - Part of the key added to the datastore
- **generation** (u64, optional): The number of times this has been updated
- **hex** (hex, optional): The hex data which has removed from the datastore
- **string** (string, optional): The data as a string, if it's valid utf-8

[comment]: # (GENERATE-FROM-SCHEMA-END)

The following error codes may occur:

- 1200: the key does not exist
- 1201: the key does exist, but the generation is wrong
- -32602: invalid parameters

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listdatastore(7), lightning-datastore(7), lightning-datastoreusage(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:7eaa7b42799aa2a1ee0719abd3e1c12cd135c1031b6c363ae52e339aa5670a47)
