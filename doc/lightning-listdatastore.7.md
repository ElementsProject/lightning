lightning-listdatastore -- Command for listing (plugin) data
============================================================

SYNOPSIS
--------

**listdatastore** [*key*] 

DESCRIPTION
-----------

The **listdatastore** RPC command allows plugins to fetch data which was stored in the Core Lightning database.

- **key** (one of, optional):
  - (array of strings): All immediate children of the *key* (or root children) are returned.
    Using the first element of the key as the plugin name (e.g. `[ 'summary' ]`) is recommended.
    An array of values to form a hierarchy (though a single value is treated as a one-element array).
    - (string, optional)
  - (string)

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listdatastore#1",
  "method": "listdatastore",
  "params": {
    "key": [
      "commando"
    ]
  }
}
{
  "id": "example:listdatastore#2",
  "method": "listdatastore",
  "params": {
    "key": "otherkey"
  }
}
```

RETURN VALUE
------------

On success, an object containing **datastore** is returned. It is an array of objects, where each object contains:

- **key** (array of strings):
  - (string, optional): Part of the key added to the datastore.
- **generation** (u64, optional): The number of times this has been updated.
- **hex** (hex, optional): The hex data from the datastore.
- **string** (string, optional): The data as a string, if it's valid utf-8.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "datastore": []
}
{
  "datastore": [
    {
      "key": [
        "otherkey"
      ],
      "generation": 0,
      "hex": "6f7468657264617461",
      "string": "otherdata"
    }
  ]
}
```

ERRORS
------

The following error codes may occur:

- -32602: invalid parameters.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-datastore(7), lightning-deldatastore(7), lightning-datastoreusage(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
