#ifndef LIBWALLY_CORE_CRYPTO_H
#define LIBWALLY_CORE_CRYPTO_H

#include "wally_core.h"

#include <stdint.h>
#include <stdlib.h>

/**
 * Derive a pseudorandom key from inputs using an expensive application
 * of HMAC SHA-256.
 *
 * @pass: Password to derive from.
 * @pass_len: Length of @pass in bytes.
 * @salt: Salt to derive from.
 * @salt_len: Length of @salt in bytes.
 * @cost: The cost of the function. The larger this number, the
 *        longer the key will take to derive.
 * @block_size: The size of memory blocks required.
 * @parallelism: Parallelism factor.
 * @bytes_out: Destination for the derived pseudorandom key.
 * @len: The length of @bytes_out in bytes.
 */
WALLY_CORE_API int wally_scrypt(
    const unsigned char *pass,
    size_t pass_len,
    const unsigned char *salt,
    size_t salt_len,
    uint32_t cost,
    uint32_t block_size,
    uint32_t parallelism,
    unsigned char *bytes_out,
    size_t len);


#define AES_BLOCK_LEN   16 /** Length of AES encrypted blocks */

#define AES_KEY_LEN_128 16 /** AES-128 Key length */
#define AES_KEY_LEN_192 24 /** AES-192 Key length */
#define AES_KEY_LEN_256 32 /** AES-256 Key length */

#define AES_FLAG_ENCRYPT  1 /** Encrypt */
#define AES_FLAG_DECRYPT  2 /** Decrypt */

/**
 * Encrypt/decrypt data using AES (ECB mode, no padding).
 *
 * @key: Key material for initialisation.
 * @key_len: Length of @key in bytes. Must be an AES_KEY_LEN_ constant.
 * @bytes_in: Bytes to encrypt/decrypt.
 * @len_in: Length of @bytes_in in bytes. Must be a multiple of @AES_BLOCK_LEN.
 * @flags: AES_FLAG_ constants indicating the desired behaviour.
 * @bytes_out: Destination for the encrypted/decrypted data.
 * @len: The length of @bytes_out in bytes. Must be a multiple of @AES_BLOCK_LEN.
 */
WALLY_CORE_API int wally_aes(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Encrypt/decrypt data using AES (CBC mode).
 *
 * @key: Key material for initialisation.
 * @key_len: Length of @key in bytes. Must be an AES_KEY_LEN_ constant.
 * @iv: Initialisation vector.
 * @iv_len: Length of @iv in bytes. Must be @AES_BLOCK_LEN.
 * @bytes_in: Bytes to encrypt/decrypt.
 * @len_in: Length of @bytes_in in bytes. Must be a multiple of @AES_BLOCK_LEN.
 * @flags: AES_FLAG_ constants indicating the desired behaviour.
 * @bytes_out: Destination for the encrypted/decrypted data.
 * @len: The length of @bytes_out in bytes. Must be a multiple of @AES_BLOCK_LEN.
 * @written: Destination for the number of bytes written to @bytes_out.
 *
 * Defaults to PKCS#7 padding.
 */
WALLY_CORE_API int wally_aes_cbc(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *iv,
    size_t iv_len,
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);


/** Output length for @wally_sha256 */
#define SHA256_LEN 32

/** Output length for @wally_sha512 */
#define SHA512_LEN 64

/**
 * SHA-256(m)
 *
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting hash.
 * @len: The length of @bytes_out in bytes. Must be @SHA256_LEN.
 */
WALLY_CORE_API int wally_sha256(
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);

/**
 * SHA-256(SHA-256(m)) (double SHA-256)
 *
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting hash.
 * @len: The length of @bytes_out in bytes. Must be @SHA256_LEN.
 */
WALLY_CORE_API int wally_sha256d(
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);

/**
 * SHA-512(m)
 *
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting hash.
 * @len: The length of @bytes_out in bytes. Must be @SHA512_LEN.
 */
WALLY_CORE_API int wally_sha512(
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);

/** Output length for @wally_hash160 */
#define HASH160_LEN 20

/**
 * RIPEMD-160(SHA-256(m))
 *
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting hash.
 * @len: The length of @bytes_out in bytes. Must be @HASH160_LEN.
 */
WALLY_CORE_API int wally_hash160(
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);


/** Output length for @wally_hmac_sha256 */
#define HMAC_SHA256_LEN 32

/** Output length for @wally_hmac_sha512 */
#define HMAC_SHA512_LEN 64

/**
 * Compute an HMAC using SHA-256
 *
 * @key: The key for the hash
 * @key_len: The length of @key in bytes.
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting HMAC.
 * @len: The length of @bytes_out in bytes. Must be @HMAC_SHA256_LEN.
 */
WALLY_CORE_API int wally_hmac_sha256(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);

/**
 * Compute an HMAC using SHA-512
 *
 * @key: The key for the hash
 * @key_len: The length of @key in bytes.
 * @bytes_in: The message to hash
 * @len_in: The length of @bytes_in in bytes.
 * @bytes_out: Destination for the resulting HMAC.
 * @len: The length of @bytes_out in bytes. Must be @HMAC_SHA512_LEN.
 */
WALLY_CORE_API int wally_hmac_sha512(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);


/** Extra bytes required at the end of 'salt_in_out' for pbkdf2 functions */
#define PBKDF2_HMAC_EXTRA_LEN 4

/** Output length for @wally_pbkdf2_hmac_sha256 */
#define PBKDF2_HMAC_SHA256_LEN 32

/** Output length for @wally_pbkdf2_hmac_sha512 */
#define PBKDF2_HMAC_SHA512_LEN 64

/** For hmac functions, indicates that 'salt_in_out' contains
 * @PBKDF2_HMAC_EXTRA_LEN extra bytes for the block number to be added into.
 */
#define PBKDF2_HMAC_FLAG_BLOCK_RESERVED 1


/**
 * Derive a pseudorandom key from inputs using HMAC SHA-256.
 *
 * @pass: Password to derive from.
 * @pass_len: Length of @pass in bytes.
 * @salt_in_out: Salt to derive from. If @flags contains the value
 *        @PBKDF2_HMAC_FLAG_BLOCK_RESERVED then this memory must
 *        have @PBKDF2_HMAC_EXTRA_LEN of spare room at the end of the salt itself.
 * @salt_len: Length of @salt_in_out in bytes, including any extra spare bytes.
 * @flags: PBKDF2_HMAC_FLAG_ flag values indicating desired behaviour.
 * @cost: The cost of the function. The larger this number, the
 *        longer the key will take to derive.
 * @bytes_out: Destination for the derived pseudorandom key.
 * @len: The length of @bytes_out in bytes. This must be a multiple
 *       of @PBKDF2_HMAC_SHA256_LEN.
 *
 * Returns 0 on success or non-zero if any parameter is invalid.
 */
WALLY_CORE_API int wally_pbkdf2_hmac_sha256(
    const unsigned char *pass,
    size_t pass_len,
    unsigned char *salt_in_out,
    size_t salt_len,
    uint32_t flags,
    uint32_t cost,
    unsigned char *bytes_out,
    size_t len);

/**
 * Derive a pseudorandom key from inputs using HMAC SHA-512.
 *
 * @pass: Password to derive from.
 * @pass_len: Length of @pass in bytes.
 * @salt_in_out: Salt to derive from. If @flags contains the value
 *        @PBKDF2_HMAC_FLAG_BLOCK_RESERVED then this memory must
 *        have @PBKDF2_HMAC_EXTRA_LEN of spare room at the end of the salt itself.
 * @salt_len: Length of @salt_in_out in bytes, including any extra spare bytes.
 * @flags: PBKDF2_HMAC_FLAG_ flag values indicating desired behaviour.
 * @cost: The cost of the function. The larger this number, the
 *        longer the key will take to derive.
 * @bytes_out: Destination for the derived pseudorandom key.
 * @len: The length of @bytes_out in bytes. This must be a multiple
 *       of @PBKDF2_HMAC_SHA512_LEN.
 *
 * Returns 0 on success or non-zero if any parameter is invalid.
 */
WALLY_CORE_API int wally_pbkdf2_hmac_sha512(
    const unsigned char *pass,
    size_t pass_len,
    unsigned char *salt_in_out,
    size_t salt_len,
    uint32_t flags,
    uint32_t cost,
    unsigned char *bytes_out,
    size_t len);

/** The length of a private key used for EC signing */
#define EC_PRIVATE_KEY_LEN 32
/** The length of a public key used for EC signing */
#define EC_PUBLIC_KEY_LEN 33
/** The length of an uncompressed public key */
#define EC_PUBLIC_KEY_UNCOMPRESSED_LEN 65
/** The length of a message hash to EC sign */
#define EC_MESSAGE_HASH_LEN 32
/** The length of a compact signature produced by EC signing */
#define EC_SIGNATURE_LEN 64
/** The maximum encoded length of a DER encoded signature */
#define EC_SIGNATURE_DER_MAX_LEN 72

/** Indicates that a signature using ECDSA/secp256k1 is required */
#define EC_FLAG_ECDSA 0x1
/** Indicates that a signature using EC-Schnorr-SHA256 is required */
#define EC_FLAG_SCHNORR 0x2


/**
 * Verify that a private key is valid.
 *
 * @priv_key: The private key to validate.
 * @priv_key_len: The length of @priv_key in bytes. Must be @EC_PRIVATE_KEY_LEN.
 */
WALLY_CORE_API int wally_ec_private_key_verify(
    const unsigned char *priv_key,
    size_t priv_key_len);

/**
 * Create a public key from a private key.
 *
 * @priv_key: The private key to create a public key from.
 * @priv_key_len: The length of @priv_key in bytes. Must be @EC_PRIVATE_KEY_LEN.
 * @bytes_out: Destination for the resulting public key.
 * @len: The length of @bytes_out in bytes. Must be @EC_PUBLIC_KEY_LEN.
 */
WALLY_CORE_API int wally_ec_public_key_from_private_key(
    const unsigned char *priv_key,
    size_t priv_key_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Create an uncompressed public key from a compressed public key.
 *
 * @pub_key: The private key to create a public key from.
 * @pub_key_len: The length of @pub_key in bytes. Must be @EC_PUBLIC_KEY_LEN.
 * @bytes_out: Destination for the resulting public key.
 * @len: The length of @bytes_out in bytes. Must be @EC_PUBLIC_KEY_UNCOMPRESSED_LEN.
 */
WALLY_CORE_API int wally_ec_public_key_decompress(
    const unsigned char *pub_key,
    size_t pub_key_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Sign a message hash with a private key, producing a compact signature.
 *
 * @priv_key: The private key to sign with.
 * @priv_key_len: The length of @priv_key in bytes. Must be @EC_PRIVATE_KEY_LEN.
 * @bytes_in: The message hash to sign.
 * @len_in: The length of @bytes_in in bytes. Must be @EC_MESSAGE_HASH_LEN.
 * @flags: EC_FLAG_ flag values indicating desired behaviour.
 * @bytes_out: Destination for the resulting compact signature.
 * @len: The length of @bytes_out in bytes. Must be @EC_SIGNATURE_LEN.
 */
WALLY_CORE_API int wally_ec_sig_from_bytes(
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Convert a signature to low-s form.
 *
 * @sig_in: The compact signature to convert.
 * @sig_in_len: The length of @sig_in in bytes. Must be @EC_SIGNATURE_LEN.
 * @bytes_out: Destination for the resulting low-s signature.
 * @len: The length of @bytes_out in bytes. Must be @EC_SIGNATURE_LEN.
 */
WALLY_CORE_API int wally_ec_sig_normalize(
    const unsigned char *sig_in,
    size_t sig_in_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Convert a compact signature to DER encoding.
 *
 * @sig_in: The compact signature to convert.
 * @sig_in_len: The length of @sig_in in bytes. Must be @EC_SIGNATURE_LEN.
 * @bytes_out: Destination for the resulting DER encoded signature.
 * @len: The length of @bytes_out in bytes. Must be @EC_SIGNATURE_DER_MAX_LEN.
 * @written: Destination for the number of bytes written to @bytes_out.
 */
WALLY_CORE_API int wally_ec_sig_to_der(
    const unsigned char *sig_in,
    size_t sig_in_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Convert a DER encoded signature to a compact signature.
 *
 * @bytes_in: The DER encoded signature to convert.
 * @len_in: The length of @sig_in in bytes.
 * @bytes_out: Destination for the resulting compact signature.
 * @len: The length of @bytes_out in bytes. Must be @EC_SIGNATURE_LEN.
 */
WALLY_CORE_API int wally_ec_sig_from_der(
    const unsigned char *bytes_in,
    size_t len_in,
    unsigned char *bytes_out,
    size_t len);

/**
 * Verify a signed message hash.
 *
 * @pub_key: The public key to verify with.
 * @pub_key_len: The length of @pub_key in bytes. Must be @EC_PUBLIC_KEY_LEN.
 * @bytes_in: The message hash to verify.
 * @len_in: The length of @bytes_in in bytes. Must be @EC_MESSAGE_HASH_LEN.
 * @flags: EC_FLAG_ flag values indicating desired behaviour.
 * @sig_in: The compact signature of the message in @bytes_in.
 * @sig_in_len: The length of @sig_in in bytes. Must be @EC_SIGNATURE_LEN.
 */
WALLY_CORE_API int wally_ec_sig_verify(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *bytes_in,
    size_t len_in,
    uint32_t flags,
    const unsigned char *sig_in,
    size_t sig_in_len);

/** The maximim size of input message that can be formatted */
#define BITCOIN_MESSAGE_MAX_LEN (64 * 1024 - 64)

/** Indicates that SHA256D(message) should be returned */
#define BITCOIN_MESSAGE_FLAG_HASH 1

/**
 * Format a message for use as a bitcoin signed message.
 *
 * @bytes_in: The message string to sign.
 * @len_in: The length of @bytes_in in bytes. Must be less than
 *          or equal to BITCOIN_MESSAGE_MAX_LEN.
 * @flags: BITCOIN_MESSAGE_FLAG_ flags indicating the desired output.
 *         if BITCOIN_MESSAGE_FLAG_HASH is passed, the double SHA256 hash
 *         of the message is placed in @bytes_out instead of the formatted
 *         message. In this case @len must be at least @SHA256_LEN.
 * @bytes_out: Destination for the formatted message or message hash.
 * @len: The length of @bytes_out in bytes.
 * @written: Destination for the number of bytes written to @bytes_out.
 */
WALLY_CORE_API int wally_format_bitcoin_message(const unsigned char *bytes_in,
                                                size_t len_in,
                                                uint32_t flags,
                                                unsigned char *bytes_out,
                                                size_t len,
                                                size_t *written);

#endif /* LIBWALLY_CORE_CRYPTO_H */
