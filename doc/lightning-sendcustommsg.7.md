lightning-sendcustommsg -- Low-level interface to send protocol messages to peers
=====================================================================================

SYNOPSIS
--------

**sendcustommsg** *node\_id* *msg*

DESCRIPTION
-----------

The `sendcustommsg` RPC method allows the user to inject a custom message
into the communication with the peer with the given `node_id`. This is
intended as a low-level interface to implement custom protocol extensions on
top, not for direct use by end-users.

The message must be a hex encoded well-formed message, including the 2-byte
type prefix, but excluding the length prefix which will be added by the RPC
method. The message types may not be one of the internally handled
types, since that may cause issues with the internal state tracking of
Core Lightning. We do (as of *v23.11*) allow sending of even types, but note that peers (as per the spec) will disconnect on receiving unknown even types.

The node specified by `node_id` must be a peer, i.e., it must have a direct
connection with the node receiving the RPC call, and the connection must be
established. For a method to send arbitrary messages over multiple hops,
including hops that do not understand the custom message, see the
`createonion` and `sendonion` RPC methods. Messages can only be injected if
the connection is handled by `openingd` or `channeld`. Messages cannot be
injected when the peer is handled by `onchaind` or `closingd` since these do
not have a connection, or are synchronous daemons that do not handle
spontaneous messages.

On the reveiving end a plugin may implement the `custommsg` plugin hook and
get notified about incoming messages, and allow additional unknown even types in their getmanifest response.

RETURN VALUE
------------

The method will validate the arguments and queue the message for delivery
through the daemon that is currently handling the connection. Queuing provides
best effort guarantees and the message may not be delivered if the connection
is terminated while the message is queued. The RPC method will return as soon
as the message is queued.

If any of the above limitations is not respected the method returns an
explicit error message stating the issue.

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **status** (string): Information about where message was queued

[comment]: # (GENERATE-FROM-SCHEMA-END)

AUTHOR
------

Christian Decker <<decker.christian@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-createonion(7), lightning-sendonion(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:0f455705de4f2f2e3d4ed8471ec3d0bf77865d8cf769884fe2b5eca40879fcaa)
