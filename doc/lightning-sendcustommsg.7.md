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

On the receiving end a plugin may implement the `custommsg` plugin hook and
get notified about incoming messages, and allow additional unknown even types 
in their getmanifest response.

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

[comment]: # ( SHA256STAMP:5603fac5f46c7f91c625b33d98df1a2a587262788465ebd1db24433989425a2e)
