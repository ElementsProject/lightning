lightning-listsqlschemas -- Command to example lightning-sql schemas
====================================================================

SYNOPSIS
--------

**listsqlschemas** [*table*] 

DESCRIPTION
-----------

Command *added* in v23.02.

This allows you to examine the schemas at runtime; while they are fully documented for the current release in lightning-sql(7), as fields are added or deprecated, you can use this command to determine what fields are present.

If *table* is given, only that table is in the resulting list, otherwise all tables are listed.

- **table** (string, optional)

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listsqlschemas#1",
  "method": "listsqlschemas",
  "params": {
    "table": "offers"
  }
}
{
  "id": "example:listsqlschemas#2",
  "method": "listsqlschemas",
  "params": [
    "closedchannels"
  ]
}
```

RETURN VALUE
------------

On success, an object containing **schemas** is returned. It is an array of objects, where each object contains:

- **tablename** (string): The name of the table.
- **columns** (array of objects): The columns, in database order.:
  - **name** (string): The name of the column.
  - **type** (string) (one of "INTEGER", "BLOB", "TEXT", "REAL"): The SQL type of the column.
- **indices** (array of arrays, optional): Any index we created to speed lookups.:
  - (array of strings): The columns for this index.
    - (string, optional): The column name.

EXAMPLE JSON RESPONSE
---------------------

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
{
  "schemas": [
    {
      "tablename": "closedchannels",
      "columns": [
        {
          "name": "rowid",
          "type": "INTEGER"
        },
        {
          "name": "peer_id",
          "type": "BLOB"
        },
        {
          "name": "channel_id",
          "type": "BLOB"
        },
        {
          "name": "short_channel_id",
          "type": "TEXT"
        },
        {
          "name": "alias_local",
          "type": "TEXT"
        },
        {
          "name": "alias_remote",
          "type": "TEXT"
        },
        {
          "name": "opener",
          "type": "TEXT"
        },
        {
          "name": "closer",
          "type": "TEXT"
        },
        {
          "name": "private",
          "type": "INTEGER"
        },
        {
          "name": "total_local_commitments",
          "type": "INTEGER"
        },
        {
          "name": "total_remote_commitments",
          "type": "INTEGER"
        },
        {
          "name": "total_htlcs_sent",
          "type": "INTEGER"
        },
        {
          "name": "funding_txid",
          "type": "BLOB"
        },
        {
          "name": "funding_outnum",
          "type": "INTEGER"
        },
        {
          "name": "leased",
          "type": "INTEGER"
        },
        {
          "name": "funding_fee_paid_msat",
          "type": "INTEGER"
        },
        {
          "name": "funding_fee_rcvd_msat",
          "type": "INTEGER"
        },
        {
          "name": "funding_pushed_msat",
          "type": "INTEGER"
        },
        {
          "name": "total_msat",
          "type": "INTEGER"
        },
        {
          "name": "final_to_us_msat",
          "type": "INTEGER"
        },
        {
          "name": "min_to_us_msat",
          "type": "INTEGER"
        },
        {
          "name": "max_to_us_msat",
          "type": "INTEGER"
        },
        {
          "name": "last_commitment_txid",
          "type": "BLOB"
        },
        {
          "name": "last_commitment_fee_msat",
          "type": "INTEGER"
        },
        {
          "name": "close_cause",
          "type": "TEXT"
        }
      ]
    }
  ]
}
```

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-sql(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
