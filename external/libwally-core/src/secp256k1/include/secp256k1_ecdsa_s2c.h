#ifndef SECP256K1_ECDSA_S2C_H
#define SECP256K1_ECDSA_S2C_H

#include "secp256k1.h"

/** This module implements the sign-to-contract scheme for ECDSA signatures, as
 *  well as the "ECDSA Anti-Exfil Protocol" that is based on sign-to-contract
 *  and is specified further down. The sign-to-contract scheme allows creating a
 *  signature that also commits to some data. This works by offsetting the public
 *  nonce point of the signature R by hash(R, data)*G where G is the secp256k1
 *  group generator.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Data structure that holds a sign-to-contract ("s2c") opening information.
 *  Sign-to-contract allows a signer to commit to some data as part of a signature. It
 *  can be used as an Out-argument in certain signing functions.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use secp256k1_ecdsa_s2c_opening_serialize and secp256k1_ecdsa_s2c_opening_parse.
 */
typedef struct {
    unsigned char data[64];
} secp256k1_ecdsa_s2c_opening;

/** Parse a sign-to-contract opening.
 *
 *  Returns: 1 if the opening could be parsed
 *           0 if the opening could not be parsed
 *  Args:    ctx: a secp256k1 context object.
 *  Out: opening: pointer to an opening object. If 1 is returned, it is set to a
 *                parsed version of input. If not, its value is unspecified.
 *  In:  input33: pointer to 33-byte array with a serialized opening
 *
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_s2c_opening_parse(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_s2c_opening* opening,
    const unsigned char* input33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a sign-to-contract opening into a byte sequence.
 *
 *  Returns: 1 if the opening was successfully serialized.
 *           0 if the opening could not be serialized
 *  Args:     ctx: a secp256k1 context object
 *  Out: output33: pointer to a 33-byte array to place the serialized opening in
 *  In:   opening: a pointer to an initialized `secp256k1_ecdsa_s2c_opening`
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_s2c_opening_serialize(
    const secp256k1_context* ctx,
    unsigned char* output33,
    const secp256k1_ecdsa_s2c_opening* opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Same as secp256k1_ecdsa_sign, but s2c_data32 is committed to inside the nonce
 *
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the private key was invalid.
 *  Args:    ctx:  pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig:  pointer to an array where the signature will be placed (cannot be NULL)
 *   s2c_opening:  if non-NULL, pointer to an secp256k1_ecdsa_s2c_opening structure to populate
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 *    s2c_data32: pointer to a 32-byte data to commit to in the nonce (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_s2c_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    secp256k1_ecdsa_s2c_opening* s2c_opening,
    const unsigned char* msg32,
    const unsigned char* seckey,
    const unsigned char* s2c_data32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Verify a sign-to-contract commitment.
 *
 *  Returns: 1: the signature contains a commitment to data32 (though it does
 *              not necessarily need to be a valid siganture!)
 *           0: incorrect opening
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature containing the sign-to-contract commitment (cannot be NULL)
 *        data32: the 32-byte data that was committed to (cannot be NULL)
 *       opening: pointer to the opening created during signing (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_s2c_verify_commit(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *data32,
    const secp256k1_ecdsa_s2c_opening *opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);


/** ECDSA Anti-Exfil Protocol
 *
 *  The ecdsa_anti_exfil_* functions can be used to prevent a signing device from
 *  exfiltrating the secret signing keys through biased signature nonces. The general
 *  idea is that a host provides additional randomness to the signing device client
 *  and the client commits to the randomness in the nonce using sign-to-contract.
 *
 *  The following scheme is described by Stepan Snigirev here:
 *    https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-February/017655.html
 *  and by Pieter Wuille (as "Scheme 6") here:
 *    https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-March/017667.html
 *
 *  In order to ensure the host cannot trick the signing device into revealing its
 *  keys, or the signing device to bias the nonce despite the host's contributions,
 *  the host and client must engage in a commit-reveal protocol as follows:
 *  1. The host draws randomness `rho` and computes a sha256 commitment to it using
 *     `secp256k1_ecdsa_anti_exfil_host_commit`. It sends this to the signing device.
 *  2. The signing device computes a public nonce `R` using the host's commitment
 *     as auxiliary randomness, using `secp256k1_ecdsa_anti_exfil_signer_commit`.
 *     The signing device sends the resulting `R` to the host as a s2c_opening.
 *
 *     If, at any point from this step onward, the hardware device fails, it is
 *     okay to restart the protocol using **exactly the same `rho`** and checking
 *     that the hardware device proposes **exactly the same** `R`. Otherwise, the
 *     hardware device may be selectively aborting and thereby biasing the set of
 *     nonces that are used in actual signatures.
 *
 *     It takes many (>100) such aborts before there is a plausible attack, given
 *     current knowledge in 2020. However such aborts accumulate even across a total
 *     replacement of all relevant devices (but not across replacement of the actual
 *     signing keys with new independently random ones).
 *
 *     In case the hardware device cannot be made to sign with the given `rho`, `R`
 *     pair, wallet authors should alert the user and present a very scary message
 *     implying that if this happens more than even a few times, say 20 or more times
 *     EVER, they should change hardware vendors and perhaps sweep their coins.
 *
 *  3. The host replies with `rho` generated in step 1.
 *  4. The device signs with `secp256k1_anti_exfil_sign`, using `rho` as `host_data32`,
 *     and sends the signature to the host.
 *  5. The host verifies that the signature's public nonce matches the opening from
 *     step 2 and its original randomness `rho`, using `secp256k1_anti_exfil_host_verify`.
 *
 *  Rationale:
 *      - The reason for having a host commitment is to allow the signing device to
 *        deterministically derive a unique nonce even if the host restarts the protocol
 *        using the same message and keys. Otherwise the signer might reuse the original
 *        nonce in two iterations of the protocol with different `rho`, which leaks the
 *        the secret key.
 *      - The signer does not need to check that the host commitment matches the host's
 *        claimed `rho`. Instead it re-derives the commitment (and its original `R`) from
 *        the provided `rho`. If this differs from the original commitment, the result
 *        will be an invalid `s2c_opening`, but since `R` was unique there is no risk to
 *        the signer's secret keys. Because of this, the signing device does not need to
 *        maintain any state about the progress of the protocol.
 */

/** Create the initial host commitment to `rho`. Part of the ECDSA Anti-Exfil Protocol.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:              ctx: pointer to a context object (cannot be NULL)
 *  Out: rand_commitment32: pointer to 32-byte array to store the returned commitment (cannot be NULL)
 *  In:             rand32: the 32-byte randomness to commit to (cannot be NULL). It must come from
 *                          a cryptographically secure RNG. As per the protocol, this value must not
 *                          be revealed to the client until after the host has received the client
 *                          commitment.
 */
SECP256K1_API int secp256k1_ecdsa_anti_exfil_host_commit(
    const secp256k1_context* ctx,
    unsigned char* rand_commitment32,
    const unsigned char* rand32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Compute signer's original nonce. Part of the ECDSA Anti-Exfil Protocol.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:    s2c_opening: pointer to an s2c_opening where the signer's public nonce will be
 *                       placed. (cannot be NULL)
 *  In:           msg32: the 32-byte message hash to be signed (cannot be NULL)
 *             seckey32: the 32-byte secret key used for signing (cannot be NULL)
 *    rand_commitment32: the 32-byte randomness commitment from the host (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_anti_exfil_signer_commit(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_s2c_opening* s2c_opening,
    const unsigned char* msg32,
    const unsigned char* seckey32,
    const unsigned char* rand_commitment32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Same as secp256k1_ecdsa_sign, but commits to host randomness in the nonce. Part of the
 *  ECDSA Anti-Exfil Protocol.
 *
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the private key was invalid.
 *  Args:    ctx:  pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig:  pointer to an array where the signature will be placed (cannot be NULL)
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 *   host_data32: pointer to 32-byte host-provided randomness (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char* msg32,
    const unsigned char* seckey,
    const unsigned char* host_data32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify a signature was correctly constructed using the ECDSA Anti-Exfil Protocol.
 *
 *  Returns: 1: the signature is valid and contains a commitment to host_data32
 *           0: incorrect opening
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature produced by the signer (cannot be NULL)
 *     msghash32: the 32-byte message hash being verified (cannot be NULL)
 *        pubkey: pointer to the signer's public key (cannot be NULL)
 *   host_data32: the 32-byte data provided by the host (cannot be NULL)
 *       opening: the s2c opening provided by the signer (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_anti_exfil_host_verify(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey,
    const unsigned char *host_data32,
    const secp256k1_ecdsa_s2c_opening *opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECDSA_S2C_H */
