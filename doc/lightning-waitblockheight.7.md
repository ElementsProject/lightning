lightning-waitblockheight -- Command for waiting for blocks on the blockchain
=============================================================================

SYNOPSIS
--------

**waitblockheight** *blockheight* \[*timeout*\]

DESCRIPTION
-----------

The **waitblockheight** RPC command waits until the blockchain
has reached the specified *blockheight*.
It will only wait up to *timeout* seconds (default 60).

If the *blockheight* is a present or past block height, then this
command returns immediately.

RETURN VALUE
------------

Once the specified block height has been achieved by the blockchain,
an object with the single field *blockheight* is returned, which is
the block height at the time the command returns.

If *timeout* seconds is reached without the specified blockheight
being reached, this command will fail.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
