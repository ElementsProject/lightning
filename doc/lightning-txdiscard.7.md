lightning-txdiscard -- Abandon a transaction from txprepare, release inputs
===========================================================================

SYNOPSIS
--------

**txdiscard** *txid*

DESCRIPTION
-----------

The **txdiscard** RPC command releases inputs which were reserved for
use of the *txid* from lightning-txprepare(7).

RETURN VALUE
------------

On success, an object with attributes *unsigned\_tx* and *txid* will be
returned, exactly as from lightning-txprepare(7).

If there is no matching *txid*, an error is reported. Note that this may
happen due to incorrect usage (such as **txdiscard** or **txsend**
already being called for *txid*) or due to lightningd restarting, which
implicitly calls **txdiscard** on all outputs.

The following error codes may occur:
- -1: An unknown *txid*.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-txprepare(7), lightning-txsend(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

