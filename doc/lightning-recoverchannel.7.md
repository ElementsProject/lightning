lightning-recoverchannel -- Command for recovering channels bundeled in an array in the form of *Static Backup*
===============================================================================================================

SYNOPSIS
--------

**recoverchannel** *scb* 

DESCRIPTION
-----------

The **recoverchannel** RPC command tries to force the peer (with whom you already had a channel) to close the channel and sweeps on-chain fund. This method is not spontaneous and depends on the peer, so use it in case of severe data loss.

The *scb* parameter is an array containing minimum required info to reconnect and sweep funds. You can get the scb for already stored channels by using the RPC command 'staticbackup'.

- **scb** (array of hexs): SCB of the channels in an array.:
  - (hex, optional)

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:recoverchannel#1",
  "method": "recoverchannel",
  "params": [
    [
      "0000000000000001c3a7b9d74a174497122bc52d74d6d69836acadc77e0429c6d8b68b48d5c9139a022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d5904017f0000019f0bc3a7b9d74a174497122bc52d74d6d69836acadc77e0429c6d8b68b48d5c9139a0000000000000000000186a000021000"
    ]
  ]
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **stubs** (array of strings):
  - (string, optional): Channel IDs of channels successfully inserted.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "stubs": [
    "c3a7b9d74a174497122bc52d74d6d69836acadc77e0429c6d8b68b48d5c9139a"
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
