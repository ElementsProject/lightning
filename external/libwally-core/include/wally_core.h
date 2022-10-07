#ifndef WALLY_CORE_H
#define WALLY_CORE_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WALLY_CORE_API
# if defined(_WIN32)
#  ifdef WALLY_CORE_BUILD
#   define WALLY_CORE_API __declspec(dllexport)
#  else
#   define WALLY_CORE_API
#  endif
# elif defined(__GNUC__) && defined(WALLY_CORE_BUILD)
#  define WALLY_CORE_API __attribute__ ((visibility ("default")))
# else
#  define WALLY_CORE_API
# endif
#endif

/** Return codes */
#define WALLY_OK      0 /** Success */
#define WALLY_ERROR  -1 /** General error */
#define WALLY_EINVAL -2 /** Invalid argument */
#define WALLY_ENOMEM -3 /** malloc() failed */

/**
 * Initialize wally.
 *
 * This function must be called once before threads are created by the application.
 *
 * :param flags: Flags controlling what to initialize. Currently must be zero.
 */
WALLY_CORE_API int wally_init(uint32_t flags);

/**
 * Free any internally allocated memory.
 *
 * :param flags: Flags controlling what to clean up. Currently must be zero.
 */
WALLY_CORE_API int wally_cleanup(uint32_t flags);

#ifndef SWIG
/**
 * Fetch the wally internal secp256k1 context object.
 *
 * By default, a single global context is created on demand. This behaviour
 * can be overriden by providing a custom context fetching function when
 * calling `wally_set_operations`.
 */
WALLY_CORE_API struct secp256k1_context_struct *wally_get_secp_context(void);

/**
 * Create a new wally-suitable secp256k1 context object.
 *
 * The created context is initialised to be usable by all wally functions.
 */
WALLY_CORE_API struct secp256k1_context_struct *wally_get_new_secp_context(void);

/**
 * Free a secp256k1 context object created by `wally_get_new_secp_context`.
 *
 * This function must only be called on context objects returned from
 * `wally_get_new_secp_context`, it should not be called on the default
 * context returned from `wally_get_secp_context`.
 */
WALLY_CORE_API void wally_secp_context_free(struct secp256k1_context_struct *ctx);
#endif

/**
 * Securely wipe memory.
 *
 * :param bytes: Memory to wipe
 * :param bytes_len: Size of ``bytes`` in bytes.
 */
WALLY_CORE_API int wally_bzero(
    void *bytes,
    size_t bytes_len);

/**
 * Securely wipe and then free a string allocated by the library.
 *
 * :param str: String to free (must be NUL terminated UTF-8).
 */
WALLY_CORE_API int wally_free_string(
    char *str);

/** Length of entropy required for ``wally_randomize_context`` */
#define WALLY_SECP_RANDOMIZE_LEN 32

/**
 * Provide entropy to randomize the libraries internal libsecp256k1 context.
 *
 * Random data is used in libsecp256k1 to blind the data being processed,
 * making side channel attacks more difficult. By default, Wally uses a single
 * internal context for secp functions that is not initially randomized.
 *
 * The caller should call this function before using any functions that rely on
 * libsecp256k1 (i.e. Anything using public/private keys). If the caller
 * has overriden the library's default libsecp context fetching using
 * `wally_set_operations`, then it may be necessary to call this function
 * before calling wally functions in each thread created by the caller.
 *
 * If wally is used in its default configuration, this function should either
 * be called before threads are created or access to wally functions wrapped
 * in an application level mutex.
 *
 * :param bytes: Entropy to use.
 * :param bytes_len: Size of ``bytes`` in bytes. Must be ``WALLY_SECP_RANDOMIZE_LEN``.
 */
WALLY_CORE_API int wally_secp_randomize(
    const unsigned char *bytes,
    size_t bytes_len);

/**
 * Verify that a hexadecimal string is valid.
 *
 * :param hex: String to verify.
 */
WALLY_CORE_API int wally_hex_verify(
    const char *hex);

/**
 * Verify that a known-length hexadecimal string is valid.
 *
 * See `wally_hex_verify`.
 */
WALLY_CORE_API int wally_hex_n_verify(
    const char *hex,
    size_t hex_len);

/**
 * Convert bytes to a (lower-case) hexadecimal string.
 *
 * :param bytes: Bytes to convert.
 * :param bytes_len: Size of ``bytes`` in bytes.
 * :param output: Destination for the resulting hexadecimal string.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_hex_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    char **output);

/**
 * Convert a hexadecimal string to bytes.
 *
 * :param hex: String to convert.
 * :param bytes_out: Where to store the resulting bytes.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the number of bytes written to ``bytes_out``.
 */
WALLY_CORE_API int wally_hex_to_bytes(
    const char *hex,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Convert a known-length hexadecimal string to bytes.
 *
 * See `wally_hex_to_bytes`.
 */
WALLY_CORE_API int wally_hex_n_to_bytes(
    const char *hex,
    size_t hex_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/* For ``wally_base58_from_bytes``, indicates that a checksum should
 * be generated. For ``wally_base58_to_bytes``, indicates that the
 * embedded checksum should be validated and stripped off the returned
 * bytes.
 */
#define BASE58_FLAG_CHECKSUM 0x1

/** The number of extra bytes required to hold a base58 checksum */
#define BASE58_CHECKSUM_LEN 4

/**
 * Create a base 58 encoded string representing binary data.
 *
 * :param bytes: Binary data to convert.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param flags: Pass ``BASE58_FLAG_CHECKSUM`` if ``bytes`` should have a
 *|    checksum calculated and appended before converting to base 58.
 * :param output: Destination for the base 58 encoded string representing ``bytes``.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_base58_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    char **output);

/**
 * Decode a base 58 encoded string back into into binary data.
 *
 * :param str_in: Base 58 encoded string to decode.
 * :param flags: Pass ``BASE58_FLAG_CHECKSUM`` if ``bytes_out`` should have a
 *|    checksum validated and removed before returning. In this case, ``len``
 *|    must contain an extra ``BASE58_CHECKSUM_LEN`` bytes to calculate the
 *|    checksum into. The returned length will not include the checksum.
 * :param bytes_out: Destination for converted binary data.
 * :param len: The length of ``bytes_out`` in bytes.
 * :param written: Destination for the length of the decoded bytes.
 */
WALLY_CORE_API int wally_base58_to_bytes(
    const char *str_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Decode a known-length base 58 encoded string back into into binary data.
 *
 * See `wally_base58_to_bytes`.
 */
WALLY_CORE_API int wally_base58_n_to_bytes(
    const char *str_in,
    size_t str_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Return the length of a base 58 encoded string once decoded into bytes.
 *
 * Returns the exact number of bytes that would be required to store ``str_in``
 * as decoded binary, including any embedded checksum. If the string contains
 * invalid characters then WALLY_EINVAL is returned. Note that no checksum
 * validation takes place.
 *
 * In the worst case (an all zero buffer, represented by a string of '1'
 * characters), this function will return strlen(``str_in``). You can therefore
 * safely use the length of ``str_in`` as a buffer size to avoid calling this
 * function in most cases.
 *
 * :param str_in: Base 58 encoded string to find the length of.
 * :param written: Destination for the length of the decoded bytes.
 *
 */
WALLY_CORE_API int wally_base58_get_length(
    const char *str_in,
    size_t *written);

/**
 * Return the length of a known-length base 58 encoded string once decoded into bytes.
 *
 * See `wally_base58_get_length`.
 */
WALLY_CORE_API int wally_base58_n_get_length(
    const char *str_in,
    size_t str_len,
    size_t *written);

/**
 * Create a base64 encoded string representing binary data.
 *
 * :param bytes: Binary data to convert.
 * :param bytes_len: The length of ``bytes`` in bytes.
 * :param flags: Must be 0.
 * :param output: Destination for the base64 encoded string representing ``bytes``.
 *|    The string returned should be freed using `wally_free_string`.
 */
WALLY_CORE_API int wally_base64_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t flags,
    char **output);

/**
 * Decode a base64 encoded string back into into binary data.
 *
 * :param str_in: Base64 encoded string to decode.
 * :param flags: Must be 0.
 * :param bytes_out: Destination for converted binary data.
 * :param len: The length of ``bytes_out`` in bytes. See ``wally_base64_get_maximum_length``.
 * :param written: Destination for the length of the decoded bytes.
 */
WALLY_CORE_API int wally_base64_to_bytes(
    const char *str_in,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Return the maximum length of a base64 encoded string once decoded into bytes.
 *
 * Since base64 strings may contain line breaks and padding, it is not
 * possible to compute their decoded length without fully decoding them.
 * This function cheaply calculates the maximum possible decoded length,
 * which can be used to allocate a buffer for ``wally_base64_to_bytes``.
 * In most cases the decoded data will be shorter than the value returned.
 *
 * :param str_in: Base64 encoded string to find the length of.
 * :param flags: Must be 0.
 * :param written: Destination for the maximum length of the decoded bytes.
 *
 */
WALLY_CORE_API int wally_base64_get_maximum_length(
    const char *str_in,
    uint32_t flags,
    size_t *written);


#ifndef SWIG
/** The type of an overridable function to allocate memory */
typedef void *(*wally_malloc_t)(
    size_t size);

/** The type of an overridable function to free memory */
typedef void (*wally_free_t)(
    void *ptr);

/** The type of an overridable function to clear memory */
typedef void (*wally_bzero_t)(
    void *ptr, size_t len);

/** The type of an overridable function to generate an EC nonce */
typedef int (*wally_ec_nonce_t)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
    );

/** The type of an overridable function to return a secp context */
typedef struct secp256k1_context_struct *(*secp_context_t)(
    void);

/** Structure holding function pointers for overridable wally operations */
struct wally_operations {
    uintptr_t struct_size; /* Must be initialised to sizeof(wally_operations) */
    wally_malloc_t malloc_fn;
    wally_free_t free_fn;
    wally_bzero_t bzero_fn;
    wally_ec_nonce_t ec_nonce_fn;
    secp_context_t secp_context_fn;
    void *reserved_1; /* reserved_ pointers are reserved for future use */
    void *reserved_2;
    void *reserved_3;
    void *reserved_4;
};

/**
 * Fetch the current overridable operations used by wally.
 *
 * :param output: Destination for the overridable operations.
 */
WALLY_CORE_API int wally_get_operations(
    struct wally_operations *output);

/**
 * Set the current overridable operations used by wally.
 *
 * :param ops: The overridable operations to set.
 *
 * .. note:: Any NULL members in the passed structure are ignored.
 */
WALLY_CORE_API int wally_set_operations(
    const struct wally_operations *ops);

#endif /* SWIG */

/**
 * Determine if the library was built with elements support.
 *
 * :param written: 1 if the library supports elements, otherwise 0.
 */
WALLY_CORE_API int wally_is_elements_build(size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* WALLY_CORE_H */
