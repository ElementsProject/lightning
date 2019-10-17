lightning-encrypthsm -- Encrypt your hsm_secret
===============================================

SYNOPSIS
--------

**encrypthsm** *password*

DESCRIPTION
-----------

The `hsm_secret` file in your lightning-dir comports a seed from which is
derived the HD wallet master key.

The **encrypthsm** command allows you to encrypt this seed with a provided *password*.

Note however that the RPC connection is not encrypted and that your password will be
transmitted in clear (in addition to being in your command history if you use the CLI).
You can use the `--encrypted-hsm` startup option, which hide your password as you type
it, as an alternative.

Once your `hsm_secret` is encrypted, you will have to explicitly start `lightningd` with
the `--encrypted-hsm` option.

The algorithm used to derive the encryption key from the password is
[Argon2id](https://github.com/p-h-c/phc-winner-argon2). The seed is then encrypted using
[xChacha20Poly1305](https://tools.ietf.org/html/draft-arciszewski-xchacha-03).

RETURN VALUE
------------

An error can be returned in two main cases:
- encryption failed, in which case the error description will give more details
- hsm_secret failure (either opening, creating, or writing), in which case the JSONRPC
    error field will be populated with the errno.

AUTHOR
------

Antoine Poinsot <<darosior@protonmail.com>>.

SEE ALSO
--------

lightning-decrypthsm(7)
lightningd-config(5)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
