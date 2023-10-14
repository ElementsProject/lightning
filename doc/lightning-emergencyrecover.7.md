lightning-emergencyrecover -- Command for recovering channels from the emergency.recovery file in the lightning directory
=========================================================================================================================

SYNOPSIS
--------

**emergencyrecover**

DESCRIPTION
-----------

The **emergencyrecover** RPC command fetches data from the emergency.recover
file and tries to reconnect to the peer and force him to close the channel.
The data in this file has enough information to reconnect and sweep the funds.

This recovery method is not spontaneous and it depends on the peer, so it should
be used as a last resort to recover the funds stored in a channel in case of severe
data loss.

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
