#ifndef LIBWALLY_CORE_BIP38_H
#define LIBWALLY_CORE_BIP38_H

#include "wally_core.h"

#include <stdint.h>

/** Flags for BIP38 conversion. The first 8 bits are reserved for the network */
#define BIP38_KEY_MAINNET       0  /** Address is for main network */
#define BIP38_KEY_TESTNET       7  /** Address is for test network */
#define BIP38_KEY_COMPRESSED   256 /** Public key is compressed */
#define BIP38_KEY_EC_MULT      512 /** EC-Multiplied key (FIXME: Not implemented) */
#define BIP38_KEY_QUICK_CHECK 1024 /** Check structure only (no password required) */
#define BIP38_KEY_RAW_MODE    2048 /** Treat bytes in as raw data */
#define BIP38_KEY_SWAP_ORDER  4096 /** Hash comes after encrypted key */

#define BIP38_SERIALIZED_LEN 39 /** Length of a raw BIP38 key in bytes */


/**
 * Encode a private key in raw BIP 38 address format.
 *
 * @bytes_in Private key to use.
 * @len_in Size of @bytes_in in bytes. Must be 32.
 * @pass Password for the encoded private key.
 * @pass_len Length of @pass in bytes.
 * @flags BIP38_KEY_ flags indicating desired behaviour.
 * @bytes_out Destination for the resulting raw BIP38 address.
 * @len Size of @bytes_out in bytes. Must be @BIP38_SERIALIZED_LEN.
 */
WALLY_CORE_API int bip38_raw_from_private_key(
    const unsigned char *bytes_in,
    size_t len_in,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Encode a private key in BIP 38 address format.
 *
 * @bytes_in Private key to use.
 * @len_in Size of @bytes_in in bytes. Must be 32.
 * @pass Password for the encoded private key.
 * @pass_len Length of @pass in bytes.
 * @flags BIP38_KEY_ flags indicating desired behaviour.
 * @output Destination for the resulting BIP38 address.
 */
WALLY_CORE_API int bip38_from_private_key(
    const unsigned char *bytes_in,
    size_t len_in,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    char **output);

/**
 * Decode a raw BIP 38 address to a private key.
 *
 * @bytes_in Raw BIP 38 address to decode.
 * @len_in Size of @bytes_in in bytes. Must be @BIP38_SERIALIZED_LEN.
 * @pass Password for the encoded private key.
 * @pass_len Length of @pass in bytes.
 * @flags BIP38_KEY_ flags indicating desired behaviour.
 * @bytes_out Destination for the resulting private key.
 * @len Size of @bytes_out in bytes. Must be 32.
 */
WALLY_CORE_API int bip38_raw_to_private_key(
    const unsigned char *bytes_in,
    size_t len_in,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Decode a BIP 38 address to a private key.
 *
 * @bip38 BIP 38 address to decode.
 * @pass Password for the encoded private key.
 * @pass_len Length of @pass in bytes.
 * @flags BIP38_KEY_ flags indicating desired behaviour.
 * @bytes_out Destination for the resulting private key.
 * @len Size of @bytes_out in bytes. Must be 32.
 */
WALLY_CORE_API int bip38_to_private_key(
    const char *bip38,
    const unsigned char *pass,
    size_t pass_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

#endif /* LIBWALLY_CORE_BIP38_H */
