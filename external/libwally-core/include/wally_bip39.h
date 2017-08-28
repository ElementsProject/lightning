#ifndef LIBWALLY_CORE_BIP39_H
#define LIBWALLY_CORE_BIP39_H

#include "wally_core.h"

#include <stdint.h>

struct words;

/** Valid entropy lengths */
#define BIP39_ENTROPY_LEN_128 16
#define BIP39_ENTROPY_LEN_160 20
#define BIP39_ENTROPY_LEN_192 24
#define BIP39_ENTROPY_LEN_224 28
#define BIP39_ENTROPY_LEN_256 32
#define BIP39_ENTROPY_LEN_288 36
#define BIP39_ENTROPY_LEN_320 40

/** The required size of the output buffer for @bip39_mnemonic_to_seed */
#define BIP39_SEED_LEN_512 64

/** The number of words in a BIP39 compliant wordlist */
#define BIP39_WORDLIST_LEN 2048

/**
 * Get the list of default supported languages.
 *
 * The string returned should be freed using @wally_free_string.
 */
WALLY_CORE_API int bip39_get_languages(
    char **output);

/**
 * Get the default word list for language @lang.
 *
 * If @lang is NULL or not found the default English list is returned.
 *
 * The returned structure should not be freed.
 */
WALLY_CORE_API int bip39_get_wordlist(
    const char *lang,
    const struct words **output);

/**
 * Get the 'index'th word from a word list.
 *
 * @w Word list to use. Pass NULL to use the default English list.
 * @index The 0-based index of the word in @w.
 * @output Destination for the resulting word.
 *
 * The string returned should be freed using @wally_free_string.
 */
WALLY_CORE_API int bip39_get_word(
    const struct words *w,
    size_t index,
    char **output);

/**
 * Generate a mnemonic sentence from the entropy in @bytes_in.
 * @w Word list to use. Pass NULL to use the default English list.
 * @bytes_in: Entropy to convert.
 * @len_in: The length of @bytes_in in bytes.
 * @output Destination for the resulting mnemonic sentence.
 *
 * The string returned should be freed using @wally_free_string.
 */
WALLY_CORE_API int bip39_mnemonic_from_bytes(
    const struct words *w,
    const unsigned char *bytes_in,
    size_t len_in,
    char **output);

/**
 * Convert a mnemonic sentence into entropy at @bytes_out.
 * @w Word list to use. Pass NULL to use the default English list.
 * @mnemonic Mnemonic to convert.
 * @bytes_out: Where to store the resulting entropy.
 * @len: The length of @bytes_out in bytes.
 * @written: Destination for the number of bytes written to @bytes_out.
 */
WALLY_CORE_API int bip39_mnemonic_to_bytes(
    const struct words *w,
    const char *mnemonic,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Validate the checksum embedded in the mnemonic sentence @mnemonic.
 * @w Word list to use. Pass NULL to use the default English list.
 * @mnemonic Mnemonic to validate.
 */
WALLY_CORE_API int bip39_mnemonic_validate(
    const struct words *w,
    const char *mnemonic);

/**
 * Convert a mnemonic into a binary seed.
 * @mnemonic Mnemonic to convert.
 * @password Mnemonic password or NULL if no password is needed.
 * @bytes_out The destination for the binary seed.
 * @len The length of @bytes_out in bytes. Currently This must
 *      be @BIP39_SEED_LEN_512.
 * @written: Destination for the number of bytes written to @bytes_out.
 */
WALLY_CORE_API int bip39_mnemonic_to_seed(
    const char *mnemonic,
    const char *password,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#endif /* LIBWALLY_CORE_BIP39_H */
