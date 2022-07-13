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
- **unsigned_tx** (hex): the unsigned transaction
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

[comment]: # ( SHA256STAMP:8a6857f312d202e3328443d6ca25b5318d6b5d8fe5655ff6c70466e54c5cd42d)
