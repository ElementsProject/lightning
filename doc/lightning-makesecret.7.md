lightning-makesecret -- Command for deriving pseudorandom key from HSM
=====================================================================

SYNOPSIS
--------

**makesecret** [*hex*] [*string*]

DESCRIPTION
-----------

The **makesecret** RPC command derives a secret key from the HSM\_secret.

One of *hex* or *string* must be specified: *hex* can be any hex data,
*string* is a UTF-8 string interpreted literally.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **secret** (secret): the pseudorandom key derived from HSM\_secret (always 64 characters)

[comment]: # (GENERATE-FROM-SCHEMA-END)


The following error codes may occur:
- -1: Catchall nonspecific error.

AUTHOR
------

Aditya <<aditya.sharma20111@gmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:5560433bde5292bad74eab0b688d8e6baa0a51562670a4f486d41b4eb2103ca8)
