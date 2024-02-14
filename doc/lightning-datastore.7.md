lightning-datastore -- Command for storing (plugin) data
========================================================

SYNOPSIS
--------

**datastore** *key* [*string*] [*hex*] [*mode*] [*generation*] 

DESCRIPTION
-----------

The **datastore** RPC command allows plugins to store data in the Core Lightning database, for later retrieval.

- **key** (one of): A key can either have children or a value, never both: parents are created and removed automatically.:
  - (array of strings): An array of values to form a hierarchy (though a single value is treated as a one-element array). Using the first element of the key as the plugin name (e.g. `[ 'summary' ]`) is recommended.
    - (string, optional)
  - (string)
- **string** (string, optional): Data to be saved in string format.
- **hex** (hex, optional): Data to be saved in hex format.
- **mode** (string, optional) (one of "must-create", "must-replace", "create-or-replace", "must-append", "create-or-append"): Write mode to determine how the record is updated:
     * `must-create`: fails if it already exists.
     * `must-replace`: fails if it doesn't already exist.
     * `create-or-replace`: never fails.
     * `must-append`: must already exist, append this to what's already there.
     * `create-or-append`: append if anything is there, otherwise create. The default is `must-create`.
- **generation** (u64, optional): If specified, means that the update will fail if the previously-existing data is not exactly that generation. This allows for simple atomicity. This is only legal with *mode* `must-replace` or `must-append`.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:datastore#1",
  "method": "datastore",
  "params": {
    "key": [
      "test_libplugin",
      "name"
    ],
    "string": "foobar",
    "hex": null,
    "mode": "must-replace",
    "generation": null
  }
}
{
  "id": "example:datastore#2",
  "method": "datastore",
  "params": {
    "key": "somekey",
    "string": null,
    "hex": "61",
    "mode": "create-or-append",
    "generation": null
  }
}
{
  "id": "example:datastore#3",
  "method": "datastore",
  "params": {
    "key": [
      "a",
      "d",
      "e",
      "f",
      "g"
    ],
    "string": "somedatatostoreinthedatastore",
    "hex": null,
    "mode": null,
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
- **hex** (hex, optional): The hex data which has been added to the datastore.
- **string** (string, optional): The data as a string, if it's valid utf-8.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "key": [
    "test_libplugin",
    "name"
  ],
  "generation": 1,
  "hex": "666f6f626172",
  "string": "foobar"
}
{
  "key": [
    "somekey"
  ],
  "generation": 3,
  "hex": "736f6d6564617461",
  "string": "somedata"
}
{
  "key": [
    "a",
    "d",
    "e",
    "f",
    "g"
  ],
  "generation": 0,
  "hex": "736f6d6564617461746f73746f7265696e7468656461746173746f7265",
  "string": "somedatatostoreinthedatastore"
}
```

ERRORS
------

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
