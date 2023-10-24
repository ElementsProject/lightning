lightning-check -- Command for verifying parameters
==============================

SYNOPSIS
--------

**check** *command\_to\_check* [*parameters*]

DESCRIPTION
-----------

The **check** RPC command verifies another command without actually 
making any changes.

The *command\_to\_check* is the name of the relevant command.

*parameters* is the command's parameters.

This is guaranteed to be safe, and will do all checks up to the point
where something in the system would need to be altered (such as checking
that channels are in the right state, peers connected, etc).

It does not guarantee successful execution of the command in all
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

[comment]: # ( SHA256STAMP:069205c0316e7096044ef71b3fa2525e389c907b45c73177469d06e69d03873c)
