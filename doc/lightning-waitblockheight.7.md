lightning-waitblockheight -- Command for waiting for blocks on the blockchain
=============================================================================

SYNOPSIS
--------

**waitblockheight** *blockheight* [*timeout*]

DESCRIPTION
-----------

The **waitblockheight** RPC command waits until the blockchain
has reached the specified *blockheight*.
It will only wait up to *timeout* seconds (default 60).

If the *blockheight* is a present or past block height, then this
command returns immediately.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **blockheight** (u32): The current block height (>= *blockheight* parameter)

[comment]: # (GENERATE-FROM-SCHEMA-END)

If *timeout* seconds is reached without the specified blockheight
being reached, this command will fail with a code of `2000`.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:4419a83c7852353e07eaa8ac3e6786c6b1d714a9a3d981fc78adfe4a73008514)
