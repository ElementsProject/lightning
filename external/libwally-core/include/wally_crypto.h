#ifndef LIBWALLY_CORE_CRYPTO_H
#define LIBWALLY_CORE_CRYPTO_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Derive a pseudorandom key from inputs using an expensive application
 * of HMAC SHA-256.
 *
 * :param pass: Password to derive from.
 * :param pass_len: Length of ``pass`` in bytes.
 * :param salt: Salt to derive from.
 * :param salt_len: Length of ``salt`` in bytes.
 * :param cost: The cost of the function. The larger this number, the
 *|     longer the key will take to derive.
 * :param block_size: The size of memory blocks required.
 * :param parallelism: Parallelism factor.
 * :param bytes_out: Destination for the derived pseudorandom key.
 * :param len: The length of ``bytes_out`` in bytes.
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
 * :param key: Key material for initialisation.
 * :param key_len: Length of ``key`` in bytes. Must be an AES_KEY_LEN_ constant.
 * :param bytes: Bytes to encrypt/decrypt.
 * :param bytes_len: Length of ``bytes`` in bytes. Must be a multiple of ``AES_BLOCK_LEN``.
 * :param flags: AES_FLAG_ constants indicating the desired behavior.
 * :param bytes_out: Destination for the encrypted/decrypted data.
 * :param len: The length of ``bytes_out`` in bytes. Must be a multiple of ``AES_BLOCK_LEN``.
 */
WALLY_CORE_API int wally_aes(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Encrypt/decrypt data using AES (CBC mode, PKCS#7 padding).
 *
 * :param key: Key material for initialisation.
 * :param key_len: Length of ``key`` in bytes. Must be an AES_KEY_LEN_ constant.
 * :param iv: Initialisation vector.
 * :param iv_len: Length of ``iv`` in bytes. Must be ``AES_BLOCK_LEN``.
 * :param bytes: Bytes to encrypt/decrypt.
 * :param bytes_len: Length of ``bytes`` in bytes. Must be a multiple of ``AES_BLOCK_LEN``.
 * :param flags: AES_FLAG_ constants indicating the desired behavior.
 * :param bytes_out: Destination for the encrypted/decrypted data.
 * :param len: The length of ``bytes_out`` in bytes. Must be a multiple of ``AES_BLOCK_LEN``.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_aes_cbc(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *iv,
    size_t iv_len,
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);


/** Output length for `wally_sha256` */
#define SHA256_LEN 32

/** Output length for `wally_sha512` */
#define SHA512_LEN 64

/**
 * SHA-256(m)
 *
 * :param bytes: The message to hash.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``SHA256_LEN``.
 */
WALLY_CORE_API int wally_sha256(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * SHA-256(m) midstate
 *
 * :param bytes: The message to hash.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``SHA256_LEN``.
 */
WALLY_CORE_API int wally_sha256_midstate(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * SHA-256(SHA-256(m)) (double SHA-256).
 *
 * :param bytes: The message to hash.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``SHA256_LEN``.
 */
WALLY_CORE_API int wally_sha256d(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * SHA-512(m).
 *
 * :param bytes: The message to hash.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``SHA512_LEN``.
 */
WALLY_CORE_API int wally_sha512(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/** Output length for `wally_ripemd160` */
#define RIPEMD160_LEN 20

/**
 * RIPEMD-160(m).
 *
 * :param bytes: The message to hash.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``RIPEMD160_LEN``.
 */
WALLY_CORE_API int wally_ripemd160(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/** Output length for `wally_hash160` */
#define HASH160_LEN 20

/**
 * RIPEMD-160(SHA-256(m)).
 *
 * :param bytes: The message to hash.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting hash.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``HASH160_LEN``.
 */
WALLY_CORE_API int wally_hash160(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);


/** Output length for `wally_hmac_sha256` */
#define HMAC_SHA256_LEN 32

/** Output length for `wally_hmac_sha512` */
#define HMAC_SHA512_LEN 64

/**
 * Compute an HMAC using SHA-256.
 *
 * :param key: The key for the hash.
 * :param key_len: The length of ``key`` in bytes.
 * :param bytes: The message to hash.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting HMAC.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``HMAC_SHA256_LEN``.
 */
WALLY_CORE_API int wally_hmac_sha256(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Compute an HMAC using SHA-512.
 *
 * :param key: The key for the hash.
 * :param key_len: The length of ``key`` in bytes.
 * :param bytes: The message to hash.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param bytes_out: Destination for the resulting HMAC.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``HMAC_SHA512_LEN``.
 */
WALLY_CORE_API int wally_hmac_sha512(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);


/** Output length for `wally_pbkdf2_hmac_sha256` */
#define PBKDF2_HMAC_SHA256_LEN 32

/** Output length for `wally_pbkdf2_hmac_sha512` */
#define PBKDF2_HMAC_SHA512_LEN 64

/**
 * Derive a pseudorandom key from inputs using HMAC SHA-256.
 *
 * :param pass: Password to derive from.
 * :param pass_len: Length of ``pass`` in bytes.
 * :param salt: Salt to derive from.
 * :param salt_len: Length of ``salt`` in bytes.
 * :param flags: Reserved, must be 0.
 * :param cost: The cost of the function. The larger this number, the
 *|     longer the key will take to derive.
 * :param bytes_out: Destination for the derived pseudorandom key.
 * :param len: The length of ``bytes_out`` in bytes. This must be a multiple
 *|     of ``PBKDF2_HMAC_SHA256_LEN``.
 */
WALLY_CORE_API int wally_pbkdf2_hmac_sha256(
    const unsigned char *pass,
    size_t pass_len,
    const unsigned char *salt,
    size_t salt_len,
    uint32_t flags,
    uint32_t cost,
    unsigned char *bytes_out,
    size_t len);

/**
 * Derive a pseudorandom key from inputs using HMAC SHA-512.
 *
 * :param pass: Password to derive from.
 * :param pass_len: Length of ``pass`` in bytes.
 * :param salt: Salt to derive from.
 * :param salt_len: Length of ``salt`` in bytes.
 * :param flags: Reserved, must be 0.
 * :param cost: The cost of the function. The larger this number, the
 *|     longer the key will take to derive.
 * :param bytes_out: Destination for the derived pseudorandom key.
 * :param len: The length of ``bytes_out`` in bytes. This must be a multiple
 *|    of ``PBKDF2_HMAC_SHA512_LEN``.
 */
WALLY_CORE_API int wally_pbkdf2_hmac_sha512(
    const unsigned char *pass,
    size_t pass_len,
    const unsigned char *salt,
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
/** The length of a compact recoverable signature produced by EC signing */
#define EC_SIGNATURE_RECOVERABLE_LEN 65
/** The maximum encoded length of a DER encoded signature */
#define EC_SIGNATURE_DER_MAX_LEN 72
/** The maximum encoded length of a DER encoded signature created with EC_FLAG_GRIND_R */
#define EC_SIGNATURE_DER_MAX_LOW_R_LEN 71

/** Indicates that a signature using ECDSA/secp256k1 is required */
#define EC_FLAG_ECDSA 0x1
/** Indicates that a signature using EC-Schnorr-SHA256 is required */
#define EC_FLAG_SCHNORR 0x2
/** Indicates that the signature nonce should be incremented until the signature is low-R */
#define EC_FLAG_GRIND_R 0x4
/** Indicates that the signature is recoverable */
#define EC_FLAG_RECOVERABLE 0x8

/* All defined flags */
#define EC_FLAGS_ALL (0x1 | 0x2 | 0x4 | 0x8)

/**
 * Verify that a private key is valid.
 *
 * :param priv_key: The private key to validate.
 * :param priv_key_len: The length of ``priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 */
WALLY_CORE_API int wally_ec_private_key_verify(
    const unsigned char *priv_key,
    size_t priv_key_len);

/**
 * Verify that a public key is valid.
 *
 * :param pub_key: The public key to validate.
 * :param pub_key_len: The length of ``pub_key`` in bytes. Must be
 *|    ``EC_PUBLIC_KEY_LEN`` or ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN``.
 */
WALLY_CORE_API int wally_ec_public_key_verify(
    const unsigned char *pub_key,
    size_t pub_key_len);

/**
 * Create a public key from a private key.
 *
 * :param priv_key: The private key to create a public key from.
 * :param priv_key_len: The length of ``priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param bytes_out: Destination for the resulting public key.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 */
WALLY_CORE_API int wally_ec_public_key_from_private_key(
    const unsigned char *priv_key,
    size_t priv_key_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Create an uncompressed public key from a compressed public key.
 *
 * :param pub_key: The public key to decompress.
 * :param pub_key_len: The length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 * :param bytes_out: Destination for the resulting public key.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN``.
 */
WALLY_CORE_API int wally_ec_public_key_decompress(
    const unsigned char *pub_key,
    size_t pub_key_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Negates a public key.
 *
 * :param pub_key: The public key to negate.
 * :param pub_key_len: The length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 * :param bytes_out: Destination for the resulting public key.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 */
WALLY_CORE_API int wally_ec_public_key_negate(
    const unsigned char *pub_key,
    size_t pub_key_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Sign a message hash with a private key, producing a compact signature.
 *
 * :param priv_key: The private key to sign with.
 * :param priv_key_len: The length of ``priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param bytes: The message hash to sign.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be ``EC_MESSAGE_HASH_LEN``.
 * :param flags: EC_FLAG_ flag values indicating desired behavior.
 * :param bytes_out: Destination for the resulting compact signature.
 * :param len: The length of ``bytes_out`` in bytes. Must be
 *|    ``EC_SIGNATURE_LEN`` if EC_FLAG_RECOVERABLE is not set, otherwise must
 *|    be ``EC_SIGNATURE_RECOVERABLE_LEN``.
 */
WALLY_CORE_API int wally_ec_sig_from_bytes(
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);

/**
 * Convert a signature to low-s form.
 *
 * :param sig: The compact signature to convert.
 * :param sig_len: The length of ``sig`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 * :param bytes_out: Destination for the resulting low-s signature.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 */
WALLY_CORE_API int wally_ec_sig_normalize(
    const unsigned char *sig,
    size_t sig_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Convert a compact signature to DER encoding.
 *
 * :param sig: The compact signature to convert.
 * :param sig_len: The length of ``sig`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 * :param bytes_out: Destination for the resulting DER encoded signature.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_SIGNATURE_DER_MAX_LEN``.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_ec_sig_to_der(
    const unsigned char *sig,
    size_t sig_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Convert a DER encoded signature to a compact signature.
 *
 * :param bytes: The DER encoded signature to convert.
 * :param bytes_len: The length of ``sig`` in bytes.
 * :param bytes_out: Destination for the resulting compact signature.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 */
WALLY_CORE_API int wally_ec_sig_from_der(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Verify a signed message hash.
 *
 * :param pub_key: The public key to verify with.
 * :param pub_key_len: The length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 * :param bytes: The message hash to verify.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be ``EC_MESSAGE_HASH_LEN``.
 * :param flags: EC_FLAG_ flag values indicating desired behavior.
 * :param sig: The compact signature of the message in ``bytes``.
 * :param sig_len: The length of ``sig`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 */
WALLY_CORE_API int wally_ec_sig_verify(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    const unsigned char *sig,
    size_t sig_len);

/**
 * Recover compressed public key from a recoverable signature.
 *
 * :param bytes: The message hash signed.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be ``EC_MESSAGE_HASH_LEN``.
 * :param sig: The recoverable compact signature of the message in ``bytes``.
 * :param sig_len: The length of ``sig`` in bytes. Must be ``EC_SIGNATURE_RECOVERABLE_LEN``.
 * :param bytes_out: Destination for recovered public key.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 *
 * .. note:: The successful recovery of the public key guarantees the correctness of the signature.
 */
WALLY_CORE_API int wally_ec_sig_to_public_key(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *sig,
    size_t sig_len,
    unsigned char *bytes_out,
    size_t len);

/** The maximum size of input message that can be formatted */
#define BITCOIN_MESSAGE_MAX_LEN (64 * 1024 - 64)

/** Indicates that SHA256D(message) should be returned */
#define BITCOIN_MESSAGE_FLAG_HASH 1

/**
 * Format a message for use as a bitcoin signed message.
 *
 * :param bytes: The message string to sign.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be less than
 *|    or equal to BITCOIN_MESSAGE_MAX_LEN.
 * :param flags: BITCOIN_MESSAGE_FLAG_ flags indicating the desired output.
 *|    if BITCOIN_MESSAGE_FLAG_HASH is passed, the double SHA256 hash
 *|    of the message is placed in ``bytes_out`` instead of the formatted
 *|    message. In this case ``len`` must be at least ``SHA256_LEN``.
 * :param bytes_out: Destination for the formatted message or message hash.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_format_bitcoin_message(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 *
 * Compute an EC Diffie-Hellman secret in constant time.
 *
 * :param pub_key: The public key.
 * :param pub_key_len: The length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 * :param priv_key: The private key.
 * :param priv_key_len: The length of ``priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param bytes_out: Destination for the shared secret.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``SHA256_LEN``.
 */
WALLY_CORE_API int wally_ecdh(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    unsigned char *bytes_out,
    size_t len);

/** The length of a data committed using sign-to-contract (s2c) */
#define WALLY_S2C_DATA_LEN 32
/** The length of a sign-to-contract (s2c) opening */
#define WALLY_S2C_OPENING_LEN 33

/**
 * Sign a message hash with a private key, producing a compact signature which
 * commits to additional data using sign-to-contract (s2c).
 *
 * :param priv_key: The private key to sign with.
 * :param priv_key_len: The length of ``priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param bytes: The message hash to sign.
 * :param bytes_len: The length of ``bytes`` in bytes. Must be ``EC_MESSAGE_HASH_LEN``.
 * :param s2c_data: The data to commit to.
 * :param s2c_data_len: The length of ``s2c_data`` in bytes. Must be ``WALLY_S2C_DATA_LEN``.
 * :param flags: Must be ``EC_FLAG_ECDSA``.
 * :param s2c_opening_out: Destination for the resulting opening information.
 * :param s2c_opening_out_len: The length of ``s2c_opening_out`` in bytes. Must be
 *|    ``WALLY_S2C_OPENING_LEN``.
 * :param bytes_out: Destination for the resulting compact signature.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 */
WALLY_CORE_API int wally_s2c_sig_from_bytes(
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *s2c_data,
    size_t s2c_data_len,
    uint32_t flags,
    unsigned char *s2c_opening_out,
    size_t s2c_opening_out_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Verify a sign-to-contract (s2c) commitment.
 *
 * :param sig: The compact signature.
 * :param sig_len: The length of ``sig`` in bytes. Must be ``EC_SIGNATURE_LEN``.
 * :param s2c_data: The data that was committed to.
 * :param s2c_data_len: The length of ``s2c_data`` in bytes. Must be ``WALLY_S2C_DATA_LEN``.
 * :param s2c_opening: The opening information produced during signing.
 * :param s2c_opening_len: The length of ``s2c_opening`` in bytes. Must be
 *|    ``WALLY_S2C_OPENING_LEN``.
 * :param flags: Must be ``EC_FLAG_ECDSA``.
 */
WALLY_CORE_API int wally_s2c_commitment_verify(
    const unsigned char *sig,
    size_t sig_len,
    const unsigned char *s2c_data,
    size_t s2c_data_len,
    const unsigned char *s2c_opening,
    size_t s2c_opening_len,
    uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_CRYPTO_H */
