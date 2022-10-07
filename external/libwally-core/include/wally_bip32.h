#ifndef LIBWALLY_CORE_BIP32_H
#define LIBWALLY_CORE_BIP32_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The required lengths of entropy for `bip32_key_from_seed` */
#define BIP32_ENTROPY_LEN_128 16
#define BIP32_ENTROPY_LEN_256 32
#define BIP32_ENTROPY_LEN_512 64

/** Length of a BIP32 key fingerprint */
#define BIP32_KEY_FINGERPRINT_LEN 4

/** Length of an ext_key serialized using BIP32 format */
#define BIP32_SERIALIZED_LEN 78

/** Child number of the first hardened child */
#define BIP32_INITIAL_HARDENED_CHILD 0x80000000

/** The maximum number of path elements allowed in a path */
#define BIP32_PATH_MAX_LEN 255

/** Indicate that we want to derive a private key in `bip32_key_from_parent` */
#define BIP32_FLAG_KEY_PRIVATE 0x0
/** Indicate that we want to derive a public key in `bip32_key_from_parent` */
#define BIP32_FLAG_KEY_PUBLIC  0x1
/** Indicate that we want to skip hash calculation when deriving a key in `bip32_key_from_parent` */
#define BIP32_FLAG_SKIP_HASH 0x2
/** Indicate that we want the pub tweak to be added to the calculation when deriving a key in `bip32_key_from_parent` */
/** Only used with elements */
#define BIP32_FLAG_KEY_TWEAK_SUM 0x4
/** Allow a wildcard ``*`` or ``*'``/``*h`` in path string expressions */
#define BIP32_FLAG_STR_WILDCARD 0x8
/** Do not allow a leading ``m``/``M`` or ``/`` in path string expressions */
#define BIP32_FLAG_STR_BARE 0x10

/** Version codes for extended keys */
#define BIP32_VER_MAIN_PUBLIC  0x0488B21E
#define BIP32_VER_MAIN_PRIVATE 0x0488ADE4
#define BIP32_VER_TEST_PUBLIC  0x043587CF
#define BIP32_VER_TEST_PRIVATE 0x04358394

#ifdef SWIG
struct ext_key;
#else
/** An extended key */
struct ext_key {
    /** The chain code for this key */
    unsigned char chain_code[32];
    /** The Hash160 of this keys parent */
    unsigned char parent160[20];
    /** The depth of this key */
    uint8_t depth;
    unsigned char pad1[10];
    /** The private key with prefix byte 0 */
    unsigned char priv_key[33];
    /** The child number of the parent key that this key represents */
    uint32_t child_num;
    /** The Hash160 of this key */
    unsigned char hash160[20];
    /** The version code for this key indicating main/testnet and private/public */
    uint32_t version;
    unsigned char pad2[3];
    /** The public key with prefix byte 0x2 or 0x3 */
    unsigned char pub_key[33];
#ifdef BUILD_ELEMENTS
    unsigned char pub_key_tweak_sum[32];
#endif /* BUILD_ELEMENTS */
};
#endif /* SWIG */

#ifndef SWIG_PYTHON
/**
 * Free a key allocated by `bip32_key_from_seed_alloc`,
 * `bip32_key_from_seed_custom` or `bip32_key_unserialize_alloc`.
 *
 * :param hdkey: Key to free.
 */
WALLY_CORE_API int bip32_key_free(
    const struct ext_key *hdkey);
#endif /* SWIG_PYTHON */

#ifndef SWIG
/**
 * Initialize a key.
 */
WALLY_CORE_API int bip32_key_init(
    uint32_t version,
    uint32_t depth,
    uint32_t child_num,
    const unsigned char *chain_code,
    size_t chain_code_len,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *hash160,
    size_t hash160_len,
    const unsigned char *parent160,
    size_t parent160_len,
    struct ext_key *output);
#endif

/**
 * As per `bip32_key_init`, but allocates the key.
 */
WALLY_CORE_API int bip32_key_init_alloc(
    uint32_t version,
    uint32_t depth,
    uint32_t child_num,
    const unsigned char *chain_code,
    size_t chain_code_len,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *hash160,
    size_t hash160_len,
    const unsigned char *parent160,
    size_t parent160_len,
    struct ext_key **output);

#ifndef SWIG
/**
 * Create a new master extended key from entropy.
 *
 * This creates a new master key, i.e. the root of a new HD tree.
 * The entropy passed in may produce an invalid key. If this happens,
 * WALLY_ERROR will be returned and the caller should retry with
 * new entropy.
 *
 * :param bytes: Entropy to use.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be one of ``BIP32_ENTROPY_LEN_128``,
 *|     ``BIP32_ENTROPY_LEN_256`` or ``BIP32_ENTROPY_LEN_512``.
 * :param version: Either ``BIP32_VER_MAIN_PRIVATE`` or ``BIP32_VER_TEST_PRIVATE``,
 *|     indicating mainnet or testnet/regtest respectively.
 * :param hmac_key: Custom data to HMAC-SHA512 with `bytes` before creating the key. Pass
 *|             NULL to use the default BIP32 key of "Bitcoin seed".
 * :param hmac_key_len: Size of ``hmac_key`` in bytes, or 0 if ``hmac_key`` is NULL.
 * :param flags: Either ``BIP32_FLAG_SKIP_HASH`` to skip hash160 calculation, or 0.
 * :param output: Destination for the resulting master extended key.
 */
WALLY_CORE_API int bip32_key_from_seed_custom(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    const unsigned char *hmac_key,
    size_t hmac_key_len,
    uint32_t flags,
    struct ext_key *output);

/**
 * As per `bip32_key_from_seed_custom` With the default BIP32 seed.
 */
WALLY_CORE_API int bip32_key_from_seed(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    uint32_t flags,
    struct ext_key *output);
#endif

/**
 * As per `bip32_key_from_seed_custom`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
WALLY_CORE_API int bip32_key_from_seed_custom_alloc(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    const unsigned char *hmac_key,
    size_t hmac_key_len,
    uint32_t flags,
    struct ext_key **output);

/**
 * As per `bip32_key_from_seed`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
WALLY_CORE_API int bip32_key_from_seed_alloc(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    uint32_t flags,
    struct ext_key **output);

/**
 * Serialize an extended key to memory using BIP32 format.
 *
 * :param hdkey: The extended key to serialize.
 * :param flags: ``BIP32_FLAG_KEY_`` Flags indicating which key to serialize. You can not
 *|        serialize a private extended key from a public extended key.
 * :param bytes_out: Destination for the serialized key.
 * :param len: Size of ``bytes_out`` in bytes. Must be ``BIP32_SERIALIZED_LEN``.
 */
WALLY_CORE_API int bip32_key_serialize(
    const struct ext_key *hdkey,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len);


#ifndef SWIG
/**
 * Un-serialize an extended key from memory.
 *
 * :param bytes: Storage holding the serialized key.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be ``BIP32_SERIALIZED_LEN``.
 * :param output: Destination for the resulting extended key.
 */
WALLY_CORE_API int bip32_key_unserialize(
    const unsigned char *bytes,
    size_t bytes_len,
    struct ext_key *output);
#endif

/**
 * As per `bip32_key_unserialize`, but allocates the key.
 *
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
WALLY_CORE_API int bip32_key_unserialize_alloc(
    const unsigned char *bytes,
    size_t bytes_len,
    struct ext_key **output);

#ifndef SWIG
/**
 * Create a new child extended key from a parent extended key.
 *
 * :param hdkey: The parent extended key.
 * :param child_num: The child number to create. Numbers greater
 *|           than or equal to ``BIP32_INITIAL_HARDENED_CHILD`` represent
 *|           hardened keys that cannot be created from public parent
 *|           extended keys.
 * :param flags: ``BIP32_FLAG_KEY_`` Flags indicating the type of derivation wanted.
 *|       You can not derive a private child extended key from a public
 *|       parent extended key.
 * :param output: Destination for the resulting child extended key.
 */
WALLY_CORE_API int bip32_key_from_parent(
    const struct ext_key *hdkey,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key *output);
#endif

/**
 * As per `bip32_key_from_parent`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
WALLY_CORE_API int bip32_key_from_parent_alloc(
    const struct ext_key *hdkey,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key **output);

#ifndef SWIG
/**
 * Create a new child extended key from a parent extended key and a path.
 *
 * :param hdkey: The parent extended key.
 * :param child_path: The path of child numbers to create.
 * :param child_path_len: The number of child numbers in ``child_path``.
 * :param flags: ``BIP32_FLAG_`` Flags indicating the type of derivation wanted.
 * :param output: Destination for the resulting child extended key.
 */
WALLY_CORE_API int bip32_key_from_parent_path(
    const struct ext_key *hdkey,
    const uint32_t *child_path,
    size_t child_path_len,
    uint32_t flags,
    struct ext_key *output);
#endif

/**
 * As per `bip32_key_from_parent_path`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
WALLY_CORE_API int bip32_key_from_parent_path_alloc(
    const struct ext_key *hdkey,
    const uint32_t *child_path,
    size_t child_path_len,
    uint32_t flags,
    struct ext_key **output);

#ifndef SWIG
/**
 * Create a new child extended key from a parent extended key and a path string.
 *
 * :param hdkey: The parent extended key.
 * :param path_str: The BIP32 path string of child numbers to create.
 * :param child_num: The child number to use if ``path_str`` contains a ``*`` wildcard.
 * :param flags: ``BIP32_FLAG_`` Flags indicating the type of derivation wanted.
 * :param output: Destination for the resulting child extended key.
 */
int bip32_key_from_parent_path_str(
    const struct ext_key *hdkey,
    const char *path_str,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key *output);

/**
 * Create a new child extended key from a parent extended key and a known-length path string.
 *
 * See `bip32_key_from_parent_path_str`.
 */
int bip32_key_from_parent_path_str_n(
    const struct ext_key *hdkey,
    const char *path_str,
    size_t path_str_len,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key *output);
#endif

/**
 * As per `bip32_key_from_parent_path_str`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
int bip32_key_from_parent_path_str_alloc(
    const struct ext_key *hdkey,
    const char *path_str,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key **output);

/**
 * As per `bip32_key_from_parent_path_str_n`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
int bip32_key_from_parent_path_str_n_alloc(
    const struct ext_key *hdkey,
    const char *path_str,
    size_t path_str_len,
    uint32_t child_num,
    uint32_t flags,
    struct ext_key **output);

#ifdef BUILD_ELEMENTS
#ifndef SWIG
/**
 * Derive the pub tweak from a parent extended key and a path.
 *
 * :param hdkey: The parent extended key.
 * :param child_path: The path of child numbers to create.
 * :param child_path_len: The number of child numbers in ``child_path``.
 * :param bytes_out: Destination for the resulting pub tweak.
 * :param len: Length of ``bytes_out`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 */
WALLY_CORE_API int bip32_key_with_tweak_from_parent_path(
    const struct ext_key *hdkey,
    const uint32_t *child_path,
    size_t child_path_len,
    uint32_t flags,
    struct ext_key *output);
#endif

/**
 * As per `bip32_key_with_tweak_from_parent_path`, but allocates the key.
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
WALLY_CORE_API int bip32_key_with_tweak_from_parent_path_alloc(
    const struct ext_key *hdkey,
    const uint32_t *child_path,
    size_t child_path_len,
    uint32_t flags,
    struct ext_key **output);
#endif /* BUILD_ELEMENTS */

/**
 * Convert an extended key to base58.
 *
 * :param hdkey: The extended key.
 * :param flags: ``BIP32_FLAG_KEY_`` Flags indicating which key to serialize. You can not
 *|        serialize a private extended key from a public extended key.
 * :param output: Destination for the resulting key in base58.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int bip32_key_to_base58(
    const struct ext_key *hdkey,
    uint32_t flags,
    char **output);

#ifndef SWIG
/**
 * Convert a base58 encoded extended key to an extended key.
 *
 * :param base58: The extended key in base58.
 * :param output: Destination for the resulting extended key.
 */
WALLY_CORE_API int bip32_key_from_base58(
    const char *base58,
    struct ext_key *output);

/**
 * Convert a known-length base58 encoded extended key to an extended key.
 *
 * See `bip32_key_from_base58`.
 */
WALLY_CORE_API int bip32_key_from_base58_n(
    const char *base58,
    size_t base58_len,
    struct ext_key *output);
#endif

/**
 * As per `bip32_key_from_base58`, but allocates the key.
 *
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
WALLY_CORE_API int bip32_key_from_base58_alloc(
    const char *base58,
    struct ext_key **output);

/**
 * As per `bip32_key_from_base58_n`, but allocates the key.
 *
 * .. note:: The returned key should be freed with `bip32_key_free`.
 */
WALLY_CORE_API int bip32_key_from_base58_n_alloc(
    const char *base58,
    size_t base58_len,
    struct ext_key **output);

/**
 * Converts a private extended key to a public extended key. Afterwards, only public child extended
 * keys can be derived, and only the public serialization can be created.
 * If the provided key is already public, nothing will be done.
 *
 * :param hdkey: The extended key to covert.
 */
WALLY_CORE_API int bip32_key_strip_private_key(
    struct ext_key *hdkey);

/**
 * Get the BIP32 fingerprint for an extended key. Performs hash160 calculation
 * if previously skipped with ``BIP32_FLAG_SKIP_HASH``.
 *
 * :param hdkey: The extended key.
 * :param bytes_out: Destination for the fingerprint.
 * :param len: Size of ``bytes_out`` in bytes. Must be ``BIP32_KEY_FINGERPRINT_LEN``.
 */
WALLY_CORE_API int bip32_key_get_fingerprint(
    struct ext_key *hdkey,
    unsigned char *bytes_out,
    size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_BIP32_H */
