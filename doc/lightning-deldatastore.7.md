lightning-deldatastore -- Command for removing (plugin) data
============================================================

SYNOPSIS
--------

**deldatastore** *key* [*generation*] 

DESCRIPTION
-----------

The **deldatastore** RPC command allows plugins to delete data it has stored in the Core Lightning database.

The command fails if the *key* isn't present, or if *generation* is specified and the generation of the data does not exactly match.

- **key** (one of):
  - (array of strings): Key is an array of values (though a single value is treated as a one-element array), to form a heirarchy. Using the first element of the key as the plugin name (e.g. [ 'summary' ]) is recommended. A key can either have children or a value, never both: parents are created and removed automatically.
    - (string, optional)
  - (string)
- **generation** (u64, optional): If specified, means that the update will fail if the previously-existing data is not exactly that generation. This allows for simple atomicity. This is only legal with mode `must-replace` or `must-append`.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:deldatastore#1",
  "method": "deldatastore",
  "params": {
    "key": "otherkey",
    "generation": 1
  }
}
{
  "id": "example:deldatastore#2",
  "method": "deldatastore",
  "params": {
    "key": [
      "a"
    ],
    "generation": null
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **key** (array of strings):
  - (string, optional): Part of the key added to the datastore.
- **generation** (u64, optional): The number of times this has been updated.
- **hex** (hex, optional): The hex data which has removed from the datastore.
- **string** (string, optional): The data as a string, if it's valid utf-8.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "key": [
    "otherkey"
  ],
  "generation": 1,
  "hex": "6f746865726461746161",
  "string": "otherdataa"
}
{
  "key": [
    "a"
  ],
  "generation": 0,
  "hex": "6176616c",
  "string": "aval"
}
```

ERRORS
------

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
