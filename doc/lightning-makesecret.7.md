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

[comment]: # ( SHA256STAMP:3c8977e48a221ea5354f1affb1ae86b606aca2df4af32bad0a101386a12556a3)
