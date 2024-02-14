lightning-makesecret -- Command for deriving pseudorandom key from HSM
======================================================================

SYNOPSIS
--------

**makesecret** [*hex*] [*string*] 

DESCRIPTION
-----------

The **makesecret** RPC command derives a secret key from the HSM\_secret.

- **hex** (hex, optional): One of `hex` or `string` must be specified: `hex` can be any hex data.
- **string** (string, optional): One of `hex` or `string` must be specified: `string` is a UTF-8 string interpreted literally.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:makesecret#1",
  "method": "makesecret",
  "params": [
    "73636220736563726574"
  ]
}
{
  "id": "example:makesecret#2",
  "method": "makesecret",
  "params": [
    null,
    "scb secret"
  ]
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **secret** (secret): The pseudorandom key derived from HSM\_secret.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "secret": "a9a2e742405c28f059349132923a99337ae7f71168b7485496e3365f5bc664ed"
}
{
  "secret": "a9a2e742405c28f059349132923a99337ae7f71168b7485496e3365f5bc664ed"
}
```

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
