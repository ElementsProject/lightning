lightning-emergencyrecover -- Command for recovering channels from the emergency.recovery file in the lightning directory
=========================================================================================================================

SYNOPSIS
--------

**emergencyrecover** 

DESCRIPTION
-----------

The **emergencyrecover** RPC command fetches data from the emergency.recover file and tries to reconnect to the peer and force him to close the channel. The data in this file has enough information to reconnect and sweep the funds.

This recovery method is not spontaneous and it depends on the peer, so it should be used as a last resort to recover the funds stored in a channel in case of severe data loss.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:emergencyrecover#1",
  "method": "emergencyrecover",
  "params": "{}"
}
{
  "id": "example:emergencyrecover#2",
  "method": "emergencyrecover",
  "params": "{}"
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **stubs** (array of hashs):
  - (hash, optional): Channel IDs of channels successfully inserted.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "stubs": []
}
{
  "stubs": [
    "c00734472f344fdadd0bf787de182e5cf144ccda5d731b0f7c75befd1f1eff52"
  ]
}
```

AUTHOR
------

Aditya <<aditya.sharma20111@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-getsharedsecret(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
