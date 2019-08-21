LIGHTNING-DISCONNECT(7) Manual Page
===================================
lightning-disconnect - Command for disconnecting from another lightning
node.

SYNOPSIS
--------

**disconnect** *id* \[*force*\]

DESCRIPTION
-----------

The disconnect RPC command closes an existing connection to a peer,
identified by *id*, in the Lightning Network, as long as it doesn’t have
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

On success, an empty object is returned.

ERRORS
------

If *id* is invalid, an error message will be returned:

    { "code" : -1, "message" : "Peer not connected" }

If the peer has an active channel and *force* is not set, an error
message will be returned:

    { "code" : -1, "message" : "Peer is in state CHANNELD_NORMAL" }

AUTHOR
------

Michael Hawkins <<michael.hawkins@protonmail.com>>.

SEE ALSO
--------

lightning-connect(1), lightning-listpeers(1)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

------------------------------------------------------------------------

Last updated 2019-04-30 17:34:18 CEST
