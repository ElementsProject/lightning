lightning-disconnect -- Command for disconnecting from another lightning node
=============================================================================

SYNOPSIS
--------

**disconnect** *id* [*force*] 

DESCRIPTION
-----------

The disconnect RPC command closes an existing connection to a peer, identified by *id*, in the Lightning Network, as long as it doesn't have an active channel.

- **id** (pubkey): The public key of the peer to terminate the connection. It can be discovered in the output of the listpeers command, which returns a set of peers:
 {
   'peers':
   [
     {
       'id': '0563aea81...',
       'connected': true,
       ...
     }
   ]
 }
- **force** (boolean, optional): If set to True, it will disconnect even with an active channel.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:disconnect#1",
  "method": "disconnect",
  "params": {
    "id": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
    "force": false
  }
}
{
  "id": "example:disconnect#2",
  "method": "disconnect",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    "force": true
  }
}
```

RETURN VALUE
------------

On success, an empty object is returned.

EXAMPLE JSON RESPONSE
---------------------

```json
{}
{}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

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
