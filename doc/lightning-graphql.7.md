lightning-graphql -- Execute a GraphQL operation on the c-lightning node.
=========================================================================

SYNOPSIS
--------

**graphql** *operation*

DESCRIPTION
-----------

The **graphql** command executes the given GraphQL *operation* and returns the
requested data. This command is useful for requesting a subset of the data
that is available via other RPC methods, and for aggregating data that would
otherwise require calls to multiple RPC methods.

General information about GraphQL can be found at [graphql.org](https://graphql.org).

Information about other RPC methods whose data can be queried via GraphQL can
be found in the sections referenced in SEE ALSO.


EXAMPLE JSON REQUEST
------------
```json
{
  "id": 82,
  "method": "graphql",
  "params": ["{info{id}, peers{id}}"]
}
```

The example above would return the ids of the lightning node and its peers as
shown in the example response below.


RETURN VALUE
------------

On success, an object is returned containing the requested data. The format of
the data is identical to the return values documented in other sections of this
manual, with exceptions noted in those sections.

Requested non-array fields for which no data is available will generally be
returned with a `null` value, whereas array fields will be empty if no data is
available. Compatibility fields for satoshi or millisatoshi amounts are not
available via GraphQL.

On failure, any error code documented in sections relevant to the requested
data may be returned. Additionally, the following GraphQL-specific errors may
be returned:

- -32000: Error in the syntax of the supplied *operation* parameter.
- -32001: Error in one or more fields specified in *operation*.
- -32002: Error in one or more arguments specified in *operation*.
- -32003: An unimplemented GraphQL feature is specified in *operation*.


EXAMPLE JSON RESPONSE
-----
```json
{
   "info": {
      "id": "02a8ce3615c0ad897656bafcee316bc15a86bcc9712bb6dde959fdb5d23112bffa"
   },
   "peers": [
      {
         "id": "0325a64e66c27f616af474c7d4b8b1cc4db44964746ac832f0afa34c700a3f36b7"
      },
      {
         "id": "0381ae77f53337af205f2054345b8a88594020e612d5deda0390da665cda228831"
      }
   ]
}

```


AUTHOR
------

Robert Dickinson <<robert.lee.dickinson@gmail.com>>


SEE ALSO
--------

lightning-getinfo(7), lightning-listpeers(7).


RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
[comment]: # ( SHA256STAMP:a41fb9bb8e6e61bec105ff250584ae019dda93d4f97bfff53bc86d57ab6e8607)
