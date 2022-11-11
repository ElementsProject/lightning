lightning-check -- Command for verifying parameters
==============================

SYNOPSIS
--------

**check** *command\_to\_check* [*parameters*]

DESCRIPTION
-----------

The **check** RPC command verifies another command's parameters without
running it.

The *command\_to\_check* is the name of the relevant command.

*parameters* is the command's parameters.

This does not guarantee successful execution of the command in all
cases. For example, a call to lightning-getroute(7) may still fail to
find a route even if checking the parameters succeeds.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **command\_to\_check** (string): the *command\_to\_check* argument

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Mark Beckwith <<wythe@intrig.com>> and Rusty Russell
<<rusty@rustcorp.com.au>> are mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:0a799d16e3f191b6c5dbea039ba32c6824718b326a1178b1f4948461c8ba6a0b)
