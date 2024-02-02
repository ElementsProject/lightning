lightning-commando -- Command to Send a Command to a Remote Peer
================================================================

SYNOPSIS
--------

**commando** *peer\_id* *method* [*params*] [*rune*]

DESCRIPTION
-----------

The **commando** RPC command is a homage to bad 80s movies.  It also
sends a directly-connected *peer\_id* a custom message, containing a
request to run *method* (with an optional dictionary of *params*);
generally the peer will only allow you to run a command if it has
provided you with a *rune* which allows it.

RETURN VALUE
------------

On success, the return depends on the *method* invoked.

ERRORS
------

On failure, one of the following error codes may be returned:

- -32600: Usually means peer is not connected
- 19535: the local commando plugin discovered an error.
- 19536: the remote commando plugin discovered an error.
- 19537: the remote commando plugin said we weren't authorized.

It can also fail if the peer does not respond, in which case it will simply
hang awaiting a response.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> wrote the original Python
commando.py plugin, the in-tree commando plugin, and this manual page.

Christian Decker came up with the name "commando", which almost
excuses his previous adoption of the name "Eltoo".

SEE ALSO
--------

lightning-commando-rune(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:6f4406cae30cab813b3bf4e1242af914276716a057e558474e29340665ee8c2f)
