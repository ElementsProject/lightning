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

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **unsigned\_tx** (hex): the unsigned transaction
- **txid** (txid): the transaction id of *unsigned_tx*

[comment]: # (GENERATE-FROM-SCHEMA-END)

If there is no matching *txid*, an error is reported. Note that this may
happen due to incorrect usage, such as **txdiscard** or **txsend**
already being called for *txid*.

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

[comment]: # ( SHA256STAMP:f52ad03cccaea672deefada22f0a11acff9d0c4f98ccfedca12759eaa6bac057)
