lightning-check -- Command for verifying parameters
==============================

SYNOPSIS
--------

**check** *command\_to\_check* \[*parameters*\]

DESCRIPTION
-----------

The **check** RPC command verifies another command’s parameters without
running it.

The *command\_to\_check* is the name of the relevant command.

*parameters* is the command’s parameters.

This does not guarantee successful execution of the command in all
cases. For example, a call to lightning-getroute(7) may still fail to
find a route even if checking the parameters succeeds.

RETURN VALUE
------------

On success, the *command\_to\_check* is returned. On failure, the
relevant RPC error is returned.

AUTHOR
------

Mark Beckwith <<wythe@intrig.com>> and Rusty Russell
<<rusty@rustcorp.com.au>> are mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

