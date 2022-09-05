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

[comment]: # ( SHA256STAMP:47f98983bc74e75b5e9ad55ebc84771a7819717e8e41f2398d0e0227a8670044)
