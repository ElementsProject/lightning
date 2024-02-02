lightning-disconnect -- Command for disconnecting from another lightning node
=============================================================================

SYNOPSIS
--------

**disconnect** *id* [*force*]

DESCRIPTION
-----------

The disconnect RPC command closes an existing connection to a peer,
identified by *id*, in the Lightning Network, as long as it doesn't have
an active channel.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an empty object is returned.

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.

AUTHOR
------

Michael Hawkins <<michael.hawkins@protonmail.com>>.

SEE ALSO
--------

lightning-connect(1), lightning-listpeers(1)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:b0793c2fa864b0ce3bc6f1618135f28ac551dfd1b8a0127caac73fd948e62d9d)
