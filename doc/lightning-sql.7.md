lightning-sql -- Command to do complex queries on list commands
===============================================================

SYNOPSIS
--------

**sql** *query* 

DESCRIPTION
-----------

Command *added* in v23.02.

The **sql** RPC command runs the given query across a sqlite3 database created from various list commands.

When tables are accessed, it calls the below commands, so it's no faster than any other local access (though it goes to great length to cache `listnodes` and `listchannels`) which then processes the results.

It is, however faster for remote access if the result of the query is much smaller than the list commands would be.

- **query** (string): The standard sqlite3 query to run.
 Note that queries like "SELECT *" are fragile, as columns will change across releases; see lightning-listsqlschemas(7).

EXAMPLE USAGE
-------------

Here are some example using lightning-cli. Note that you may need to use `-o` if you use queries which contain `=` (which make lightning-cli(1) default to keyword style):

A simple peer selection query:

```shell
$ lightning-cli sql "SELECT id FROM peers"
{
   "rows": [
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00"
      ]
   ]
}
```

A statement containing using `=` needs `-o`:

```shell
$ lightning-cli sql -o "SELECT node_id,last_timestamp FROM nodes WHERE last_timestamp>=1669578892"
{
   "rows": [
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00",
         1669601603
      ]
   ]
}
```

If you want to compare a BLOB column, `x'hex'` or `X'hex'` are needed:

```shell
$ lightning-cli sql -o "SELECT nodeid FROM nodes WHERE nodeid != x'03c9d25b6c0ce4bde5ad97d7ab83f00ae8bd3800a98ccbee36f3c3205315147de1';"
{
   "rows": [
      [
         "0214739d625944f8fdc0da9d2ef44dbd7af58443685e494117b51410c5c3ff973a"
      ],
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00"
      ]
   ]
}
$ lightning-cli sql -o "SELECT nodeid FROM nodes WHERE nodeid IN (x'03c9d25b6c0ce4bde5ad97d7ab83f00ae8bd3800a98ccbee36f3c3205315147de1', x'02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00')"
{
   "rows": [
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00"
      ],
      [
         "03c9d25b6c0ce4bde5ad97d7ab83f00ae8bd3800a98ccbee36f3c3205315147de1"
      ]
   ]
}
```

Related tables are usually referenced by JOIN:

```shell
$ lightning-cli sql -o "SELECT nodeid, alias, nodes_addresses.type, nodes_addresses.port, nodes_addresses.address FROM nodes INNER JOIN nodes_addresses ON nodes_addresses.row = nodes.rowid"
{
   "rows": [
      [
         "02ba9965e3db660385bd1dd2c09dd032e0f2179a94fc5db8917b60adf0b363da00",
         "YELLOWWATCH-22.11rc2-31-gcd7593b",
         "dns",
         7272,
         "localhost"
      ],
      [
         "0214739d625944f8fdc0da9d2ef44dbd7af58443685e494117b51410c5c3ff973a",
         "HOPPINGSQUIRREL-1rc2-31-gcd7593b",
         "dns",
         7171,
         "localhost"
      ]
   ]
}
```

Simple function usage, in this case COUNT. Strings inside arrays need ", and ' to protect them from the shell:

```shell
$ lightning-cli sql 'SELECT COUNT(*) FROM nodes"
{
   "rows": [
      [
         3
      ]
   ]
}
```

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:sql#1",
  "method": "sql",
  "params": [
    "SELECT * FROM forwards;"
  ]
}
{
  "id": "example:sql#2",
  "method": "sql",
  "params": [
    "SELECT * from peerchannels_features"
  ]
}
```

RETURN VALUE
------------

On success, an object containing **rows** is returned. It is an array. Each array entry contains an array of values, each an integer, real number, string or *null*, depending on the sqlite3 type.

The object may contain **warning\_db\_failure** if the database fails partway through its operation.
On success, an object is returned, containing:

- **rows** (array of arrays):
  - (array)

The following warnings may also be returned:

- **warning\_db\_failure**: A message if the database encounters an error partway through.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "rows": []
}
{
  "rows": [
    [
      6,
      1,
      0,
      "option_static_remotekey"
    ],
    [
      7,
      1,
      1,
      "option_anchors_zero_fee_htlc_tx"
    ],
    [
      16,
      11,
      0,
      "option_static_remotekey"
    ],
    [
      17,
      11,
      1,
      "option_anchors_zero_fee_htlc_tx"
    ]
  ]
}
```

ERRORS
------

On failure, an error is returned.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-listtransactions(7), lightning-listchannels(7), lightning-listpeers(7), lightning-listnodes(7), lightning-listforwards(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
