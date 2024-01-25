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

[comment]: # ( SHA256STAMP:2d991663ce45ada109fd8b0bfca5cee3c9f4f59503d63a5f5b1f669f83cefc67)
