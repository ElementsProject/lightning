lightning-listpeers -- Command returning data on connected lightning nodes
==========================================================================

SYNOPSIS
--------

**listpeers** \[*id*\] \[*level*\]

DESCRIPTION
-----------

The **listpeers** RPC command returns data on nodes that are connected
or are not connected but have open channels with this node.

Once a connection to another lightning node has been established, using
the **connect** command, data on the node can be returned using
**listpeers** and the *id* that was used with the **connect** command.

If no *id* is supplied, then data on all lightning nodes that are
connected, or not connected but have open channels with this node, are
returned.

Supplying *id* will filter the results to only return data on a node
with a matching *id*, if one exists.

Supplying *level* will show log entries related to that peer at the
given log level. Valid log levels are "io", "debug", "info", and
"unusual".

If a channel is open with a node and the connection has been lost, then
the node will still appear in the output of the command and the value of
the *connected* attribute of the node will be "false".

The channel will remain open for a set blocktime, after which if the
connection has not been re-established, the channel will close and the
node will no longer appear in the command output.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **peers** is returned.  It is an array of objects, where each object contains:
- **id** (pubkey): the public key of the peer
- **connected** (boolean): True if the peer is currently connected
- **log** (array of objects, optional): if *level* is specified, logs for this peer:
  - **type** (string) (one of "SKIPPED", "BROKEN", "UNUSUAL", "INFO", "DEBUG", "IO_IN", "IO_OUT")

  If **type** is "SKIPPED":
    - **num_skipped** (u32): number of deleted/omitted entries

  If **type** is "BROKEN", "UNUSUAL", "INFO" or "DEBUG":
    - **time** (string): UNIX timestamp with 9 decimal places
    - **source** (string): The particular logbook this was found in
    - **log** (string): The actual log message
    - **node_id** (pubkey): The peer this is associated with

  If **type** is "IO_IN" or "IO_OUT":
    - **time** (string): UNIX timestamp with 9 decimal places
    - **source** (string): The particular logbook this was found in
    - **log** (string): The actual log message
    - **node_id** (pubkey): The peer this is associated with
    - **data** (hex): The IO which occurred

If **connected** is *true*:
  - **netaddr** (array of strings): A single entry array:
    - address, e.g. 1.2.3.4:1234
  - **features** (hex): bitmap of BOLT #9 features from peer's INIT message

[comment]: # (GENERATE-FROM-SCHEMA-END)

On success, an object with a "peers" key is returned containing a list
of 0 or more objects.

Each object in the list contains the following data:
- *id* : The unique id of the peer
- *connected* : A boolean value showing the connection status
- *netaddr* : A list of network addresses the node is listening on
- *features* : Bit flags showing supported features (BOLT \#9)
- *log* : Only present if *level* is set. List logs related to the
peer at the specified *level*

If *id* is supplied and no matching nodes are found, a "peers" object
with an empty list is returned.

A list of the peer's channels can be retrieved with the **listpeerchannels**
RPC command, which returns an object with a "channels" key containing a list
of 0 or more objects describing channels with the peer, optionally filtered by
peer *id* and/or channel *status*.

On error the returned object will contain `code` and `message` properties,
with `code` being one of the following:

- -32602: If the given parameters are wrong.

AUTHOR
------

Michael Hawkins <<michael.hawkins@protonmail.com>>.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel\_start(7),
lightning-setchannelfee(7), lightning-listpeerchannels(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning> Lightning
RFC site (BOLT \#9):
<https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md>

[comment]: # ( SHA256STAMP:19b44f1ef0cef45a22516cf4daa9e603f1c709d7ebd43b8aceaf992574cf236f)
