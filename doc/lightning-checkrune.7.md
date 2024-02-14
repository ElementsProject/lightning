lightning-checkrune -- Command to Validate Rune
===============================================

SYNOPSIS
--------

**checkrune** *rune* [*nodeid*] [*method*] [*params*] 

DESCRIPTION
-----------

Command *added* in v23.08.

The **checkrune** RPC command checks the validity/authorization rights of specified rune for the given nodeid, method, and params.

If successful, the rune "usage" counter (used for ratelimiting) is incremented.

See lightning-createrune(7) for the fields in the rune which are checked.

- **rune** (string): Rune to check for authorization.
- **nodeid** (string, optional): Node id of requesting node *(required until v23.11)*.
- **method** (string, optional): Method for which rune needs to be validated *(required until v23.11)*.
- **params** (one of, optional):
  - (array): Array of positional parameters.
  - (object): Parameters for method.:

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:checkrune#1",
  "method": "checkrune",
  "params": {
    "nodeid": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
    "rune": "617Obfct0oRBj_uqGFQxDk3XZ1sDFiC2Q5ltm5z1i_k9NSZtZXRob2Q9aW52b2ljZSZwbmFtZWRlc2NyaXB0aW9uPUB0aXBqYXJcfGpiNTVAc2VuZHNhdHMubG9s",
    "method": "invoice",
    "params": {
      "amount_msat": "any",
      "label": "lbl",
      "description": [
        "@tipjar|jb55@sendsats.lol."
      ]
    }
  }
}
{
  "id": "example:checkrune#2",
  "method": "checkrune",
  "params": {
    "nodeid": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
    "rune": "OSqc7ixY6F-gjcigBfxtzKUI54uzgFSA6YfBQoWGDV89MA==",
    "method": "listpeers",
    "params": {}
  }
}
{
  "id": "example:checkrune#3",
  "method": "checkrune",
  "params": {
    "nodeid": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
    "rune": "617Obfct0oRBj_uqGFQxDk3XZ1sDFiC2Q5ltm5z1i_k9NSZtZXRob2Q9aW52b2ljZSZwbmFtZWRlc2NyaXB0aW9uPUB0aXBqYXJcfGpiNTVAc2VuZHNhdHMubG9s",
    "method": "invoice",
    "params": {
      "amount_msat": "any",
      "label": "lbl",
      "description": "@tipjar|jb55@sendsats.lol"
    }
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **valid** (boolean): True if the rune is valid.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "valid": true
}
{
  "valid": true
}
{
  "valid": true
}
```

ERRORS
------

The following error codes may occur:

- 1501 (RUNE\_NOT\_AUTHORIZED): rune is not for this node (or perhaps completely invalid)
- 1502 (RUNE\_NOT\_PERMITTED): rune does not allow this usage (includes a detailed reason why)
- 1503 (RUNE\_BLACKLISTED): rune has been explicitly blacklisted.

AUTHOR
------

Shahana Farooqui <<sfarooqui@blockstream.com>> is mainly responsible for consolidating logic from commando.

SEE ALSO
--------

lightning-createrune(7), lightning-blacklistrune(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
