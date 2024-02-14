lightning-staticbackup -- Command for deriving getting SCB of all the existing channels
=======================================================================================

SYNOPSIS
--------

**staticbackup** 

DESCRIPTION
-----------

The **staticbackup** RPC command returns an object with SCB of all the channels in an array.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:staticbackup#1",
  "method": "staticbackup",
  "params": "{}"
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **scb** (array of hexs):
  - (hex, optional): SCB of a channel in TLV format.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "scb": [
    "0000000000000001c707da9b230e1655b0a6c082b8daf4fa44d9d1f68163ed4d531d45cf453dc651022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d5900017f000001b2e3c707da9b230e1655b0a6c082b8daf4fa44d9d1f68163ed4d531d45cf453dc6510000000000000000000186a000021000"
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
