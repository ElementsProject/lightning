lightning-recover -- Reinitialize Your Node for Recovery
========================================================

SYNOPSIS
--------

**recover** *hsmsecret*

DESCRIPTION
-----------

The **recover** RPC command wipes your node and restarts it with
the `--recover` option.  This is only permitted if the node is unused:
no channels, no bitcoin addresses issued (you can use `check` to see
if recovery is possible).

*hsmsecret* is either a codex32 secret starting with "cl1" as returned
by `hsmtool getcodexsecret`, or a raw 64 character hex string.

NOTE: this command only currently works with the `sqlite3` database backend.

RETURN VALUE
------------

On success, an empty object is returned, and your node is restarted.

AUTHOR
------

Rusty Russell <<rusty@blockstream.com>> is mainly responsible.

SEE ALSO
--------

lightning-hsmtool(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:9cfaa9eb4609b36accc3e3b12a352c00ddd402307e4461f4df274146d12f6eb0)
