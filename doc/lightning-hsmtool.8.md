lightning-hsmtool -- Tool for working with software HSM secrets of lightningd
=============================================================================

SYNOPSIS
--------
```bash
lightning-hsmtool method [ARGUMENTS]...
```

DESCRIPTION
-----------

**lightning-hsmtool** performs various operations on the `hsm_secret`
file used by the software HSM component of **lightningd**.

This can be used to encrypt and decrypt the `hsm_secret` file,
as well as derive secrets used in channel commitments.

METHODS
-------

 **encrypt** *hsm\_secret* *password*
Encrypt the `hsm_secret` file so that it can only be decrypted at
**lightningd** startup.
You must give the option **--encrypted-hsm** to **lightningd**.
The password of the `hsm_secret` file will be asked whenever you
start **lightningd**.

 **decrypt** *hsm\_secret* *password*
Decrypt the `hsm_secret` file that was encrypted with the **encrypt**
method.

 **dumpcommitments** *node\_id* *channel\_dbid* *depth* *hsm\_secret* \[*password*\]
Show the per-commitment secret and point of up to *depth* commitments,
of the specified channel with the specified peer,
identified by the channel database index.
Specify *password* if the `hsm_secret` is encrypted.

 **guesstoremote** *p2wpkh* *node\_id* *max\_channel\_dbid* *hsm\_secret* \[*password*\]
Brute-force the private key to our funds from a remote unilateral close
of a channel, in a case where we have lost all database data except for
our `hsm_secret`.
The peer must be the one to close the channel (and the funds will remain
unrecoverable until the channel is closed).
*max\_channel\_dbid* is your own guess on what the *channel\_dbid* was,
or at least the maximum possible value,
and is usually no greater than the number of channels that the node has
ever had.
Specify *password* if the `hsm_secret` is encrypted.

BUGS
----

You should report bugs on our github issues page, and maybe submit a fix
to gain our eternal gratitude!

AUTHOR
------
ZmnSCPxj < <ZmnSCPxj@protonmail.com> > wrote the initial version of
this man page, but many others did the hard work of actually implementing
**lightning-hsmtool**.

SEE ALSO
--------

lightningd(8), lightningd-config(5)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

COPYING
-------

Note: the modules in the ccan/ directory have their own licenses, but
the rest of the code is covered by the BSD-style MIT license.
Main web site: <https://github.com/ElementsProject/lightning>
