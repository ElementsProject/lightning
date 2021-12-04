lightning-getsharedsecret -- Command for computing an ECDH
==========================================================

SYNOPSIS
--------

**getsharedsecret** *point*

DESCRIPTION
-----------

The **getsharedsecret** RPC command computes a shared secret from a
given public *point*, and the secret key of this node.
The *point* is a hexadecimal string of the compressed public
key DER-encoding of the SECP256K1 point.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **shared_secret** (hex): the SHA-2 of the compressed encoding of the shared secp256k1 point (always 64 characters)

[comment]: # (GENERATE-FROM-SCHEMA-END)

This command may fail if communications with the HSM has a
problem;
by default lightningd uses a software "HSM" which should
never fail in this way.
(As of the time of this writing there is no true hardware
HSM that lightningd can use, but we are leaving this
possibilty open in the future.)
In that case, it will return with an error code of 800.

CRYPTOGRAPHIC STANDARDS
-----------------------

This serves as a key agreement scheme in elliptic-curve based
cryptographic standards.

However, note that most key agreement schemes based on
Elliptic-Curve Diffie-Hellman do not hash the DER-compressed
point.
Standards like SECG SEC-1 ECIES specify using the X coordinate
of the point instead.
The Lightning BOLT standard (which `lightningd` uses), unlike
most other cryptographic standards, specifies the SHA-256 hash
of the DER-compressed encoding of the point.

It is not possible to extract the X coordinate of the ECDH point
via this API, since there is no known way to reverse the 256-bit
SHA-2 hash function.
Thus there is no way to implement ECIES and similar standards using
this API.

If you know the secret key behind *point*, you do not need to
even call **getsharedsecret**, you can just multiply the secret key
with the node public key.

Typically, a sender will generate an ephemeral secret key
and multiply it with the node public key,
then use the result to derive an encryption key
for a symmetric encryption scheme
to encrypt a message that can be read only by that node.
Then the ephemeral secret key is multiplied
by the standard generator point,
and the ephemeral public key and the encrypted message is
sent to the node,
which then uses **getsharedsecret** to derive the same key.

The above sketch elides important details like
key derivation function, stream encryption scheme,
message authentication code, and so on.
You should follow an established standard and avoid
rolling your own crypto.

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> is mainly responsible.

SEE ALSO
--------

RESOURCES
---------

* BOLT 4: <https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#shared-secret>
* BOLT 8: <https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#handshake-state>
* SECG SEC-1 ECIES: <https://secg.org/sec1-v2.pdf>
* Main web site: <https://github.com/ElementsProject/lightning>


[comment]: # ( SHA256STAMP:e54898c6b950be6242a641212b71b6ce33ea31068f3572cd42be5d2b87365eb7)
