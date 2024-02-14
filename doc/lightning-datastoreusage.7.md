lightning-datastoreusage -- Command for listing datastore usage info
====================================================================

SYNOPSIS
--------

**datastoreusage** [*key*] 

DESCRIPTION
-----------

Command *added* in v23.11.

The **datastoreusage** RPC command allows the caller to fetch the total bytes that are stored under a certain *key* (or from the root), including the size of the *key*.

All descendants of the *key* (or root) are taken into account.

- **key** (one of, optional):
  - (array of strings): Key is an array of values (though a single value is treated as a one-element array). Used as the starting point to traverse the datastore.
    - (string, optional)
  - (string)

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:datastoreusage#1",
  "method": "datastoreusage",
  "params": {
    "key": null
  }
}
{
  "id": "example:datastoreusage#2",
  "method": "datastoreusage",
  "params": {
    "key": "a"
  }
}
{
  "id": "example:datastoreusage#3",
  "method": "datastoreusage",
  "params": {
    "key": [
      "a",
      "thisissomelongkeythattriestostore46bytesofdata"
    ]
  }
}
```

RETURN VALUE
------------

On success, an object containing **datastoreusage** is returned. It is an object containing:

- **key** (string): The key from which the database was traversed. *(added v23.11)*
- **total\_bytes** (u64): The total bytes that are stored under the *key*, including the all descendants data and the size of the keys themselves. *(added v23.11)*

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "datastoreusage": {
    "key": "[]",
    "total_bytes": 0
  }
}
{
  "datastoreusage": {
    "key": "[a]",
    "total_bytes": 32
  }
}
{
  "datastoreusage": {
    "key": "[a,thisissomelongkeythattriestostore46bytesofdata]",
    "total_bytes": 77
  }
}
```

AUTHOR
------

Peter Neuroth <<pet.v.ne@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-datastore(7), lightning-deldatastore(7), lightning-listdatastore(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
