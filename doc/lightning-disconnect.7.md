lightning-disconnect -- Command for disconnecting from another lightning node
=============================================================================

SYNOPSIS
--------

**disconnect** *id* [*force*]

DESCRIPTION
-----------

The disconnect RPC command closes an existing connection to a peer,
identified by *id*, in the Lightning Network, as long as it doesn't have
an active channel. If *force* is set then it will disconnect even with
an active channel.

The *id* can be discovered in the output of the listpeers command, which
returns a set of peers:

    {
         "peers": [
              {
                   "id": "0563aea81...",
                   "connected": true,
                   ...
              }
         ]
    }

Passing the *id* attribute of a peer to *disconnect* will terminate the
connection.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an empty object is returned.

[comment]: # (GENERATE-FROM-SCHEMA-END)

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

[comment]: # ( SHA256STAMP:1a64fbaed63ffee21df3d46956a6dca193982b1b135a9b095e68652a720c77ac)
