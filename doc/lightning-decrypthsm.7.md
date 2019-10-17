lightning-encrypthsm -- Decrypt your hsm_secret
===============================================

SYNOPSIS
--------

**decrypthsm** *password*

DESCRIPTION
-----------

The `hsm_secret` file in your lightning-dir comports a seed from which is
derived the HD wallet master key. If you previously encrypted it using the
`--encrypted-hsm` startup option or the `encrypthsm` RPC command, you can decrypt it
by using the **decrypthsm** RPC command with the same *password* used to encrypt it.

RETURN VALUE
------------

An error can be returned in two main cases:
- decryption failed, in which case the error description will give more details
- hsm_secret failure (either opening, creating, or writing), in which case the JSONRPC
    error field will be populated with the errno.

AUTHOR
------

Antoine Poinsot <<darosior@protonmail.com>>.

SEE ALSO
--------

lightning-encrypthsm(7)
lightningd-config(5)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
