lightning-staticbackup -- Command for deriving getting SCB of all the existing channels
======================================================================================

SYNOPSIS
--------

**staticbackup**

DESCRIPTION
-----------

The **staticbackup** RPC command returns an object with SCB of all the channels in an array.


RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **scb** (array of hexs):
  - SCB of a channel in TLV format

[comment]: # (GENERATE-FROM-SCHEMA-END)


AUTHOR
------

Aditya <<aditya.sharma20111@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-getsharedsecret(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:d76fa5580c067419d83f7103758907b8771f9c393a38ec053c3a36de03a76e9a)
