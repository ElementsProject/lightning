lightning-listsqlschemas -- Command to example lightning-sql schemas
====================================================================

SYNOPSIS
--------

**listsqlschemas** [*table*]

DESCRIPTION
-----------

This allows you to examine the schemas at runtime; while they are fully
documented for the current release in lightning-sql(7), as fields are
added or deprecated, you can use this command to determine what fields
are present.

If *table* is given, only that table is in the resulting list, otherwise
all tables are listed.

EXAMPLE JSON REQUEST
------------
```json
{
  "id": 82,
  "method": "listsqlschemas",
  "params": {
    "table": "offers"
  }
}
```

EXAMPLE JSON RESPONSE
-----
```json
{
   "schemas": [
      {
         "tablename": "offers",
         "columns": [
            {
               "name": "offer_id",
               "type": "BLOB"
            },
            {
               "name": "active",
               "type": "INTEGER"
            },
            {
               "name": "single_use",
               "type": "INTEGER"
            },
            {
               "name": "bolt12",
               "type": "TEXT"
            },
            {
               "name": "bolt12_unsigned",
               "type": "TEXT"
            },
            {
               "name": "used",
               "type": "INTEGER"
            },
            {
               "name": "label",
               "type": "TEXT"
            }
         ],
         "indices": [
            [
               "offer_id"
            ]
         ]
      }
   ]
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **schemas** is returned.  It is an array of objects, where each object contains:

- **tablename** (string): the name of the table
- **columns** (array of objects): the columns, in database order:
  - **name** (string): the name of the column
  - **type** (string): the SQL type of the column (one of "INTEGER", "BLOB", "TEXT", "REAL")
- **indices** (array of arrays, optional): Any index we created to speed lookups:
  - The columns for this index:
    - The column name

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-sql(7).

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:1b00b9a14c9b433321cbf661fdb39cebd2c5fd5239ab80c3ebb845d7705c47d0)
