lightning-recoverchannel -- Command for recovering channels bundeled in an array in the form of *Static Backup*
===============================================================================================================

SYNOPSIS
--------

**recoverchannel** *scb*

DESCRIPTION
-----------

The **recoverchannel** RPC command tries to force the peer (with whom you
already had a channel) to close the channel and sweeps on-chain fund. This
method is not spontaneous and depends on the peer, so use it in case of
severe data loss.

The *scb* parameter is an array containing minimum required info to
reconnect and sweep funds. You can get the scb for already stored channels
by using the RPC command 'staticbackup'


RETURN VALUE
------------

On success, an object is returned, containing:

- **stubs** (array of hexs):
  - Each item is the channel ID of the channel successfully inserted


AUTHOR
------

Aditya <<aditya.sharma20111@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-getsharedsecret(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:9cfaa9eb4609b36accc3e3b12a352c00ddd402307e4461f4df274146d12f6eb0)
