#ifndef LIBWALLY_CORE_SYMMETRIC_H
#define LIBWALLY_CORE_SYMMETRIC_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new symmetric parent key from entropy.
 *
 * :param bytes: Entropy to use.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be one of ``BIP32_ENTROPY_LEN_128``,
 *|     ``BIP32_ENTROPY_LEN_256`` or ``BIP32_ENTROPY_LEN_512``.
 * :param bytes_out: Destination for the resulting parent key.
 * :param len: Size of ``bytes_out`` in bytes. Must be ``HMAC_SHA512_LEN``.
 */
WALLY_CORE_API int wally_symmetric_key_from_seed(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 *
 * Create a new child symmetric key from a parent key.
 *
 * :param bytes: Parent key to use.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be ``HMAC_SHA512_LEN``.
 * :param version: Version byte to prepend to ``label``. Must be zero.
 * :param label: Label to use for the child.
 * :param label_len: Size of ``label`` in bytes.
 * :param bytes_out: Destination for the resulting key.
 * :param len: Size of ``bytes_out`` in bytes. Must be ``HMAC_SHA512_LEN``.
 */
WALLY_CORE_API int wally_symmetric_key_from_parent(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    const unsigned char *label,
    size_t label_len,
    unsigned char *bytes_out,
    size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_SYMMETRIC_H */
