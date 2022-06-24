lightning-staticbacup -- Command for deriving getting SCB of all the existing channels
======================================================================================

SYNOPSIS
--------

**staticbackup**

DESCRIPTION
-----------

The **staticbackup** RPC command returns an object with SCB of all the channels in an array.


RETURN VALUE
------------

On success, an object is returned, containing:
- **scb** (array of hexs):
  - Each item is SCB of a channel in TLV format


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
