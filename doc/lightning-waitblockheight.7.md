lightning-waitblockheight -- Command for waiting for blocks on the blockchain
=============================================================================

SYNOPSIS
--------

**waitblockheight** *blockheight* [*timeout*] 

DESCRIPTION
-----------

The **waitblockheight** RPC command waits until the blockchain has reached the specified *blockheight*.

- **blockheight** (u32): Current blockheight of the blockchain if the value is greater than this number. If it is a present or past block height, then the command returns immediately.
- **timeout** (u32, optional): Only wait up to specified seconds. The default is 60 seconds.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:waitblockheight#1",
  "method": "waitblockheight",
  "params": {
    "blockheight": 99,
    "timeout": null
  }
}
{
  "id": "example:waitblockheight#2",
  "method": "waitblockheight",
  "params": {
    "blockheight": 103,
    "timeout": 600
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **blockheight** (u32): The current block height (>= *blockheight* parameter).

If *timeout* seconds is reached without the specified blockheight being reached, this command will fail with a code of `2000`.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "blockheight": 99
}
{
  "blockheight": 103
}
```

ERRORS
------

The following error codes may occur:

- 2000: Timed out.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
