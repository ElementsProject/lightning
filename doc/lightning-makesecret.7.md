lightning-makesecret -- Command for deriving pseudorandom key from HSM
=====================================================================

SYNOPSIS
--------

**makesecret** *hex*

DESCRIPTION
-----------

The **makesecret** RPC command derives a secret key from the HSM_secret.

The *hex* can be any hex data.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **secret** (secret): the pseudorandom key derived from HSM_secret (always 64 characters)

[comment]: # (GENERATE-FROM-SCHEMA-END)


The following error codes may occur:
- -1: Catchall nonspecific error.

AUTHOR
------

Aditya <<aditya.sharma20111@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-getsharedsecret(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:1bd94ffa8440041efafe93440d9828be6baca199b0f5cb73220e4482582bf01d)
