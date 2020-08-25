lightning-txsend -- Command to sign and send transaction from txprepare
=======================================================================

SYNOPSIS
--------

**txsend** *txid*

DESCRIPTION
-----------

The **txsend** RPC command signs and broadcasts a transaction created by
**txprepare**.

RETURN VALUE
------------

On success, an object with attributes *tx* and *txid* will be returned.

*tx* represents the fully signed raw bitcoin transaction, and *txid* is
the same as the *txid* argument.

On failure, an error is reported (from bitcoind), and the inputs from
the transaction are unreserved.

The following error codes may occur:
- -1: Catchall nonspecific error.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-txprepare(7), lightning-txdiscard(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

