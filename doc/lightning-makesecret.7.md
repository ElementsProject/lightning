lightning-makesecret -- Command for deriving pseudorandom key from HSM
=====================================================================

SYNOPSIS
--------

**makesecret** [*hex*] [*string*]

DESCRIPTION
-----------

The **makesecret** RPC command derives a secret key from the HSM\_secret.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **secret** (secret): the pseudorandom key derived from HSM\_secret

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The following error codes may occur:

- -1: Catchall nonspecific error.

AUTHOR
------

Aditya <<aditya.sharma20111@gmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:098d2882774cb9f33fb8aa93b7be1bf102d96a4835c550fdda7828ab5812490d)
