lightning-getecdh -- Command for computing an ECDH
==================================================

SYNOPSIS
--------

**getecdh** *point*

DESCRIPTION
-----------

The **getecdh** RPC command computes a shared secret from a
given public *point*, and the secret key of this node.
The *point* is a hexadecimal string of the compressed public
key DER-encoding of the SECP256K1 point.

RETURN VALUE
------------

On success, **getecdh** returns a field *shared\_secret*,
which is a hexadecimal string of the compressed public key
DER-encoding of the SECP256K1 point that is the shared secret
generated using the Elliptic Curve Diffie-Hellman algorithm.
This field is 33 bytes (66 hexadecimal characters in a string).

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

This is a cryptographic primitive and is only a small part of a
full cryptographic suite of algorithms.
The returned shared secret is simply the product of the given
*point* and the node secret key, returned as a DER compressed
public key.

If you know the secret key behind *point*, you do not need to
even call **getecdh**, you can just multiply the secret key with
the node public key.

Standards vary on their definition of ECDH key agreement.

1. In Lightning BOLT specs, the product of the secret key and
   the point is DER-encoded as a compressed public key, and the
   encoded form is hashed with 256-bit SHA-2, with the resulting
   hash considered as the shared secret key.
   To work with **getecdh**, just SHA-256 hash the returned
   *shared\_secret*.
2. In SECG SEC-1 ECIES, the X coordinate of the product of
   the secret key and the point is the shared secret key.
   To work with **getecdh**, just drop the first byte of
   the returned *shared\_secret*, since the compressed DER
   encoding is just the sign of the Y coordinate followed by
   the full 256-bit X coordinate.

Typically, a sender will generate an ephemeral secret key
and multiply it with the node public key,
then use the result to derive an encryption key
for a symmetric encryption scheme
to encrypt a message that can be read only by that node.
Then the ephemeral secret key is multiplied
by the standard generator point,
and the ephemeral public key and the encrypted message is
sent to the node,
which then uses **getecdh** to derive the same key.

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

