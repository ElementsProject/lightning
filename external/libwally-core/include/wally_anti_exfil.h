#ifndef LIBWALLY_CORE_ANTI_EXFIL_H
#define LIBWALLY_CORE_ANTI_EXFIL_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BUILD_STANDARD_SECP

/** The length of the commitment to the host provided randomness */
#define WALLY_HOST_COMMITMENT_LEN 32

/**
 * Create the initial commitment to host randomness.
 *
 * :param entropy: Randomness to commit to. It must come from a
 *|    cryptographically secure RNG. As per the protocol, this value must not
 *|    be revealed to the client until after the host has received the client
 *|    commitment.
 * :param entropy_len: The length of ``entropy`` in bytes. Must be
 *|    ``WALLY_S2C_DATA_LEN``.
 * :param flags: Must be ``EC_FLAG_ECDSA``.
 * :param bytes_out: Destination for the resulting compact signature.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``WALLY_HOST_COMMITMENT_LEN``.
 */
WALLY_CORE_API int wally_ae_host_commit_from_bytes(
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Compute signer's original nonce.
 *
 * :param priv_key: The private key used for signing.
 * :param priv_key_len: The length of ``priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param bytes: The message hash to be signed.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be ``EC_MESSAGE_HASH_LEN``.
 * :param commitment: Randomness commitment from the host.
 * :param commitment_len: The length of ``commitment`` in bytes. Must be
 *|    ``WALLY_HOST_COMMITMENT_LEN``.
 * :param flags: Must be ``EC_FLAG_ECDSA``.
 * :param s2c_opening_out: Destination for the resulting opening information.
 * :param s2c_opening_out_len: The length of ``s2c_opening_out`` in bytes. Must be
 *|    ``WALLY_S2C_OPENING_LEN``.
 */
WALLY_CORE_API int wally_ae_signer_commit_from_bytes(
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *commitment,
    size_t commitment_len,
    uint32_t flags,
    unsigned char *s2c_opening_out,
    size_t s2c_opening_out_len);

/**
 * Same as ``wally_ec_sig_from_bytes``, but commits to the host randomness.
 *
 * :param priv_key: The private key to sign with.
 * :param priv_key_len: The length of ``priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param bytes: The message hash to sign.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be ``EC_MESSAGE_HASH_LEN``.
 * :param entropy: Host provided randomness.
 * :param entropy_len: The length of ``entropy`` in bytes. Must be ``WALLY_S2C_DATA_LEN``.
 * :param flags: Must be ``EC_FLAG_ECDSA``.
 * :param bytes_out: Destination for the resulting compact signature.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 */
WALLY_CORE_API int wally_ae_sig_from_bytes(
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Verify a signature was correctly constructed using the Anti-Exfil Protocol.
 *
 * :param pub_key: The public key to verify with.
 * :param pub_key_len: The length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 * :param bytes: The message hash to verify.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be ``EC_MESSAGE_HASH_LEN``.
 * :param entropy: Randomness provided by the host.
 * :param entropy_len: The length of ``entropy`` in bytes. Must be ``WALLY_S2C_DATA_LEN``.
 * :param s2c_opening: Opening information provided by the signer.
 * :param s2c_opening_len: The length of ``s2c_opening`` in bytes. Must be
 *|    ``WALLY_S2C_OPENING_LEN``.
 * :param flags: Must be ``EC_FLAG_ECDSA``.
 * :param sig: The compact signature of the message in ``bytes``.
 * :param sig_len: The length of ``sig`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 */
WALLY_CORE_API int wally_ae_verify(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *entropy,
    size_t entropy_len,
    const unsigned char *s2c_opening,
    size_t s2c_opening_len,
    uint32_t flags,
    const unsigned char *sig,
    size_t sig_len);

#endif /* ndef BUILD_STANDARD_SECP */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_ANTI_EXFIL_H */
