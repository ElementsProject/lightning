#ifndef LIBWALLY_CORE_PSBT_H
#define LIBWALLY_CORE_PSBT_H

#include "wally_transaction.h"
#include "wally_bip32.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PSBT Version number */
#define WALLY_PSBT_HIGHEST_VERSION 0

/* Ignore scriptsig and witness when adding an input */
#define WALLY_PSBT_FLAG_NON_FINAL 0x1

/* Key prefix for proprietary keys in our unknown maps */
#define PSBT_PROPRIETARY_TYPE 0xFC

#ifdef SWIG
struct wally_map;
struct wally_psbt_input;
struct wally_psbt_output;
struct wally_psbt;
#else

/** A map item */
struct wally_map_item {
    unsigned char *key;
    size_t key_len;
    unsigned char *value;
    size_t value_len;
};

/** A map of key,value pairs */
struct wally_map {
    struct wally_map_item *items;
    size_t num_items;
    size_t items_allocation_len;
};

/** A PSBT input */
struct wally_psbt_input {
    struct wally_tx *utxo;
    struct wally_tx_output *witness_utxo;
    unsigned char *redeem_script;
    size_t redeem_script_len;
    unsigned char *witness_script;
    size_t witness_script_len;
    unsigned char *final_scriptsig;
    size_t final_scriptsig_len;
    struct wally_tx_witness_stack *final_witness;
    struct wally_map keypaths;
    struct wally_map signatures;
    struct wally_map unknowns;
    uint32_t sighash;
#ifdef BUILD_ELEMENTS
    uint64_t value;
    uint32_t has_value;
    unsigned char *vbf;
    size_t vbf_len;
    unsigned char *asset;
    size_t asset_len;
    unsigned char *abf;
    size_t abf_len;
    struct wally_tx *pegin_tx;
    unsigned char *txoutproof;
    size_t txoutproof_len;
    unsigned char *genesis_blockhash;
    size_t genesis_blockhash_len;
    unsigned char *claim_script;
    size_t claim_script_len;
#endif /* BUILD_ELEMENTS */
};

/** A PSBT output */
struct wally_psbt_output {
    unsigned char *redeem_script;
    size_t redeem_script_len;
    unsigned char *witness_script;
    size_t witness_script_len;
    struct wally_map keypaths;
    struct wally_map unknowns;
#ifdef BUILD_ELEMENTS
    unsigned char *blinding_pubkey;
    size_t blinding_pubkey_len;
    unsigned char *value_commitment;
    size_t value_commitment_len;
    unsigned char *vbf;
    size_t vbf_len;
    unsigned char *asset_commitment;
    size_t asset_commitment_len;
    unsigned char *abf;
    size_t abf_len;
    unsigned char *nonce;
    size_t nonce_len;
    unsigned char *rangeproof;
    size_t rangeproof_len;
    unsigned char *surjectionproof;
    size_t surjectionproof_len;
#endif /* BUILD_ELEMENTS */
};

/** A partially signed bitcoin transaction */
struct wally_psbt {
    unsigned char magic[5];
    struct wally_tx *tx;
    struct wally_psbt_input *inputs;
    size_t num_inputs;
    size_t inputs_allocation_len;
    struct wally_psbt_output *outputs;
    size_t num_outputs;
    size_t outputs_allocation_len;
    struct wally_map unknowns;
    uint32_t version;
};
#endif /* SWIG */

/**
 * Allocate and initialize a new map.
 *
 * :param allocation_len: The number of items to allocate.
 * :param output: Destination for the new map.
 */
WALLY_CORE_API int wally_map_init_alloc(
    size_t allocation_len,
    struct wally_map **output);

#ifndef SWIG_PYTHON
/**
 * Free a map allocated by `wally_map_init_alloc`.
 *
 * :param map_in: The map to free.
 */
WALLY_CORE_API int wally_map_free(
    struct wally_map *map_in);
#endif /* SWIG_PYTHON */

/**
 * Find an item in a map.
 *
 * :param map_in: The map to find ``key`` in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_map_find(
    const struct wally_map *map_in,
    const unsigned char *key,
    size_t key_len,
    size_t *written);

/**
 * Add an item to a map.
 *
 * :param map_in: The map to add to.
 * :param key: The key to add.
 * :param key_len: Length of ``key`` in bytes.
 * :param value: The value to add.
 * :param value_len: Length of ``value`` in bytes.
 */
WALLY_CORE_API int wally_map_add(
    struct wally_map *map_in,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *value,
    size_t value_len);

/**
 * Convert and add a pubkey/keypath to a map.
 *
 * :param map_in: The map to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be ``BIP32_KEY_FINGERPRINT_LEN``.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_map_add_keypath_item(
    struct wally_map *map_in,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

/**
 * Sort the items in a map.
 *
 * :param map_in: The map to sort.
 * :param flags: Flags controlling sorting. Must be 0.
 */
WALLY_CORE_API int wally_map_sort(
    struct wally_map *map_in,
    uint32_t flags);

#ifndef SWIG
/**
 * Determine if a PSBT input is finalized.
 *
 * :param input: The input to check.
 * :param written: On success, set to one if the input is finalized, otherwise zero.
 */
WALLY_CORE_API int wally_psbt_input_is_finalized(
    const struct wally_psbt_input *input,
    size_t *written);

/**
 * Set the utxo in an input.
 *
 * :param input: The input to update.
 * :param utxo: The (non witness) utxo for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_input_set_utxo(
    struct wally_psbt_input *input,
    const struct wally_tx *utxo);

/**
 * Set the witness_utxo in an input.
 *
 * :param input: The input to update.
 * :param witness_utxo: The witness utxo for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_input_set_witness_utxo(
    struct wally_psbt_input *input,
    const struct wally_tx_output *witness_utxo);

/**
 * Set the redeem_script in an input.
 *
 * :param input: The input to update.
 * :param script: The redeem script for this input.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_redeem_script(
    struct wally_psbt_input *input,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the witness_script in an input.
 *
 * :param input: The input to update.
 * :param script: The witness script for this input.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_witness_script(
    struct wally_psbt_input *input,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the final_scriptsig in an input.
 *
 * :param input: The input to update.
 * :param final_scriptsig: The scriptSig for this input.
 * :param final_scriptsig_len: Length of ``final_scriptsig`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_final_scriptsig(
    struct wally_psbt_input *input,
    const unsigned char *final_scriptsig,
    size_t final_scriptsig_len);

/**
 * Set the final_witness in an input.
 *
 * :param input: The input to update.
 * :param final_witness: The witness stack for the input, or NULL if no witness is present.
 */
WALLY_CORE_API int wally_psbt_input_set_final_witness(
    struct wally_psbt_input *input,
    const struct wally_tx_witness_stack *final_witness);

/**
 * Set the keypaths in an input.
 *
 * :param input: The input to update.
 * :param map_in: The HD keypaths for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_keypaths(
    struct wally_psbt_input *input,
    const struct wally_map *map_in);

/**
 * Find a keypath matching a pubkey in an input.
 *
 * :param input: The input to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_input_find_keypath(
    struct wally_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    size_t *written);

/**
 * Convert and add a pubkey/keypath to an input.
 *
 * :param input: The input to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be ``BIP32_KEY_FINGERPRINT_LEN``.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_psbt_input_add_keypath_item(
    struct wally_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

/**
 * Set the partial signatures in an input.
 *
 * :param input: The input to update.
 * :param map_in: The partial signatures for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_signatures(
    struct wally_psbt_input *input,
    const struct wally_map *map_in);

/**
 * Find a partial signature matching a pubkey in an input.
 *
 * :param input: The input to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_input_find_signature(
    struct wally_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    size_t *written);

/**
 * Add a pubkey/partial signature item to an input.
 *
 * :param input: The input to add the partial signature to.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param sig: The DER-encoded signature plus sighash byte to add.
 * :param sig_len: The length of ``sig`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_add_signature(
    struct wally_psbt_input *input,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *sig,
    size_t sig_len);

/**
 * Set the unknown values in an input.
 *
 * :param input: The input to update.
 * :param map_in: The unknown key value pairs for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_unknowns(
    struct wally_psbt_input *input,
    const struct wally_map *map_in);

/**
 * Find an unknown item matching a key in an input.
 *
 * :param input: The input to search in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_input_find_unknown(
    struct wally_psbt_input *input,
    const unsigned char *key,
    size_t key_len,
    size_t *written);

/**
 * Set the sighash type in an input.
 *
 * :param input: The input to update.
 * :param sighash: The sighash type for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_sighash(
    struct wally_psbt_input *input,
    uint32_t sighash);

/**
 * Set the redeem_script in an output.
 *
 * :param output: The input to update.
 * :param script: The redeem script for this output.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_redeem_script(
    struct wally_psbt_output *output,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the witness_script in an output.
 *
 * :param output: The output to update.
 * :param script: The witness script for this output.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_witness_script(
    struct wally_psbt_output *output,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the keypaths in an output.
 *
 * :param output: The output to update.
 * :param map_in: The HD keypaths for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_keypaths(
    struct wally_psbt_output *output,
    const struct wally_map *map_in);

/**
 * Find a keypath matching a pubkey in an output.
 *
 * :param output: The output to search in.
 * :param pub_key: The pubkey to find.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_output_find_keypath(
    struct wally_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len,
    size_t *written);

/**
 * Convert and add a pubkey/keypath to an output.
 *
 * :param output: The output to add to.
 * :param pub_key: The pubkey to add.
 * :param pub_key_len: Length of ``pub_key`` in bytes. Must be ``EC_PUBLIC_KEY_UNCOMPRESSED_LEN`` or ``EC_PUBLIC_KEY_LEN``.
 * :param fingerprint: The master key fingerprint for the pubkey.
 * :param fingerprint_len: Length of ``fingerprint`` in bytes. Must be ``BIP32_KEY_FINGERPRINT_LEN``.
 * :param child_path: The BIP32 derivation path for the pubkey.
 * :param child_path_len: The number of items in ``child_path``.
 */
WALLY_CORE_API int wally_psbt_output_add_keypath_item(
    struct wally_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *fingerprint,
    size_t fingerprint_len,
    const uint32_t *child_path,
    size_t child_path_len);

/**
 * Set the unknown map in an output.
 *
 * :param output: The output to update.
 * :param map_in: The unknown key value pairs for this output.
 */
WALLY_CORE_API int wally_psbt_output_set_unknowns(
    struct wally_psbt_output *output,
    const struct wally_map *map_in);

/**
 * Find an unknown item matching a key in an output.
 *
 * :param output: The output to search in.
 * :param key: The key to find.
 * :param key_len: Length of ``key`` in bytes.
 * :param written: On success, set to zero if the item is not found, otherwise
 *|    the index of the item plus one.
 */
WALLY_CORE_API int wally_psbt_output_find_unknown(
    struct wally_psbt_output *output,
    const unsigned char *key,
    size_t key_len,
    size_t *written);
#endif /* SWIG */

/**
 * Allocate and initialize a new PSBT.
 *
 * :param version: The version of the PSBT. Must be 0.
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param global_unknowns_allocation_len: The number of global unknowns to allocate space for.
 * :param output: Destination for the resulting PSBT output.
 */
WALLY_CORE_API int wally_psbt_init_alloc(
    uint32_t version,
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    struct wally_psbt **output);

#ifndef SWIG_PYTHON
/**
 * Free a PSBT allocated by `wally_psbt_init_alloc`.
 *
 * :param psbt: The PSBT to free.
 */
WALLY_CORE_API int wally_psbt_free(
    struct wally_psbt *psbt);
#endif /* SWIG_PYTHON */

/**
 * Determine if all PSBT inputs are finalized.
 *
 * :param psbt: The PSBT to check.
 * :param written: On success, set to one if the PSBT is finalized, otherwise zero.
 */
WALLY_CORE_API int wally_psbt_is_finalized(
    const struct wally_psbt *psbt,
    size_t *written);

/**
 * Set the global transaction for a PSBT.
 *
 * :param psbt: The PSBT to set the transaction for.
 * :param tx: The transaction to set.
 *
 * The global transaction can only be set on a newly created PSBT. After this
 * call completes the PSBT will have empty inputs and outputs for each input
 * and output in the transaction ``tx`` given.
 */
WALLY_CORE_API int wally_psbt_set_global_tx(
    struct wally_psbt *psbt,
    const struct wally_tx *tx);

/**
 * Add a transaction input to PBST at a given position.
 *
 * :param psbt: The PSBT to add the input to.
 * :param index: The zero-based index of the position to add the input at.
 * :param flags: Flags controlling input insertion. Must be 0 or ``WALLY_PSBT_FLAG_NON_FINAL``.
 * :param input: The transaction input to add.
 */
WALLY_CORE_API int wally_psbt_add_input_at(
    struct wally_psbt *psbt,
    uint32_t index,
    uint32_t flags,
    const struct wally_tx_input *input);

/**
 * Remove a transaction input from a PBST.
 *
 * :param psbt: The PSBT to remove the input from.
 * :param index: The zero-based index of the input to remove.
 */
WALLY_CORE_API int wally_psbt_remove_input(
    struct wally_psbt *psbt,
    uint32_t index);

/**
 * Add a transaction output to PBST at a given position.
 *
 * :param psbt: The PSBT to add the output to.
 * :param index: The zero-based index of the position to add the output at.
 * :param flags: Flags controlling output insertion. Must be 0.
 * :param output: The transaction output to add.
 */
WALLY_CORE_API int wally_psbt_add_output_at(
    struct wally_psbt *psbt,
    uint32_t index,
    uint32_t flags,
    const struct wally_tx_output *output);

/**
 * Remove a transaction output from a PBST.
 *
 * :param psbt: The PSBT to remove the output from.
 * :param index: The zero-based index of the output to remove.
 */
WALLY_CORE_API int wally_psbt_remove_output(
    struct wally_psbt *psbt,
    uint32_t index);

/**
 * Create a PSBT from its serialized bytes.
 *
 * :param bytes: Bytes to create the PSBT from.
 * :param bytes_len: Length of ``bytes`` in bytes.
 * :param output: Destination for the resulting PSBT.
 */
WALLY_CORE_API int wally_psbt_from_bytes(
    const unsigned char *bytes,
    size_t bytes_len,
    struct wally_psbt **output);

/**
 * Get the length of a PSBT when serialized to bytes.
 *
 * :param psbt: the PSBT.
 * :param flags: Flags controlling length determination. Must be 0.
 * :param written: Destination for the length in bytes when serialized.
 */
WALLY_CORE_API int wally_psbt_get_length(
    const struct wally_psbt *psbt,
    uint32_t flags,
    size_t *written);

/**
 * Serialize a PSBT to bytes.
 *
 * :param psbt: the PSBT to serialize.
 * :param flags: Flags controlling serialization. Must be 0.
 * :param bytes_out: Bytes to create the transaction from.
 * :param len: Length of ``bytes`` in bytes (use `wally_psbt_get_length`).
 * :param written: number of bytes written to bytes_out.
 */
WALLY_CORE_API int wally_psbt_to_bytes(
    const struct wally_psbt *psbt,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Create a PSBT from its serialized base64 string.
 *
 * :param base64: Base64 string to create the PSBT from.
 * :param output: Destination for the resulting PSBT.
 */
WALLY_CORE_API int wally_psbt_from_base64(
    const char *base64,
    struct wally_psbt **output);

/**
 * Serialize a PSBT to a base64 string.
 *
 * :param psbt: the PSBT to serialize.
 * :param flags: Flags controlling serialization. Must be 0.
 * :param output: Destination for the resulting serialized PSBT.
 */
WALLY_CORE_API int wally_psbt_to_base64(
    const struct wally_psbt *psbt,
    uint32_t flags,
    char **output);

/**
 * Combine the metadata from a source PSBT into another PSBT.
 *
 * :param psbt: the PSBT to combine into.
 * :param source: the PSBT to copy data from.
 */
WALLY_CORE_API int wally_psbt_combine(
    struct wally_psbt *psbt,
    const struct wally_psbt *src);

/**
 * Clone a PSBT into a newly allocated copy.
 *
 * :param psbt: the PSBT to clone.
 * :param flags: Flags controlling PSBT creation. Must be 0.
 * :param output: Destination for the resulting cloned PSBT.
 */
WALLY_CORE_API int wally_psbt_clone_alloc(
    const struct wally_psbt *psbt,
    uint32_t flags,
    struct wally_psbt **output);

/**
 * Sign a PSBT using the simple signer algorithm.
 *
 * :param psbt: PSBT to sign. Directly modifies this PSBT.
 * :param key: Private key to sign PSBT with.
 * :param key_len: Length of key in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param flags: Flags controlling sigining. Must be 0 or EC_FLAG_GRIND_R.
 *
 * .. note:: See https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#simple-signer-algorithm
 *|    for a description of the simple signer algorithm.
 */
WALLY_CORE_API int wally_psbt_sign(
    struct wally_psbt *psbt,
    const unsigned char *key,
    size_t key_len,
    uint32_t flags);

/**
 * Finalize a PSBT.
 *
 * :param psbt: PSBT to finalize. Directly modifies this PSBT.
 */
WALLY_CORE_API int wally_psbt_finalize(
    struct wally_psbt *psbt);

/**
 * Extract a network transaction from a finalized PSBT.
 *
 * :param psbt: PSBT to extract from.
 * :param output: Destination for the resulting transaction.
 */
WALLY_CORE_API int wally_psbt_extract(
    const struct wally_psbt *psbt,
    struct wally_tx **output);

/**
 * Determine if a PSBT is an elements PSBT.
 *
 * :param psbt: The PSBT to check.
 * :param written: 1 if the PSBT is an elements PSBT, otherwise 0.
 */
WALLY_CORE_API int wally_psbt_is_elements(
    const struct wally_psbt *psbt,
    size_t *written);

#ifdef BUILD_ELEMENTS
/**
 * Allocate and initialize a new elements PSBT.
 *
 * :param version: The version of the PSBT. Must be 0.
 * :param inputs_allocation_len: The number of inputs to pre-allocate space for.
 * :param outputs_allocation_len: The number of outputs to pre-allocate space for.
 * :param global_unknowns_allocation_len: The number of global unknowns to allocate space for.
 * :param output: Destination for the resulting PSBT output.
 */
WALLY_CORE_API int wally_psbt_elements_init_alloc(
    uint32_t version,
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    struct wally_psbt **output);

#ifndef SWIG
/**
 * Set the value in an elements input.
 *
 * :param input: The input to update.
 * :param value: The value for this input.
 */
WALLY_CORE_API int wally_psbt_input_set_value(
    struct wally_psbt_input *input,
    uint64_t value);

/**
 * Clear the value in an elements input.
 *
 * :param input: The input to update.
 */
WALLY_CORE_API int wally_psbt_input_clear_value(
    struct wally_psbt_input *input);

/**
 * Set the value blinding factor in an elements input.
 *
 * :param input: The input to update.
 * :param vbf: The value blinding factor.
 * :param vbf_len: Length of ``vbf``. Must be ``BLINDING_FACTOR_LEN``.
 */
WALLY_CORE_API int wally_psbt_input_set_vbf(
    struct wally_psbt_input *input,
    const unsigned char *vbf,
    size_t vbf_len);

/**
 * Set the asset in an elements input.
 *
 * :param input: The input to update.
 * :param asset: The asset for this input.
 * :param asset_len: Length of ``asset`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_asset(
    struct wally_psbt_input *input,
    const unsigned char *asset,
    size_t asset_len);

/**
 * Set the asset blinding factor in an elements input
 *
 * :param input: The input to update.
 * :param abf: The asset blinding factor.
 * :param abf_len: Length of ``abf`` in bytes. Must be ``BLINDING_FACTOR_LEN``.
 */
WALLY_CORE_API int wally_psbt_input_set_abf(
    struct wally_psbt_input *input,
    const unsigned char *abf,
    size_t abf_len);

/**
 * Set the peg in tx in an input.
 *
 * :param input: The input to update.
 * :param pegin_tx: The peg in tx for this input if it exists.
 */
WALLY_CORE_API int wally_psbt_input_set_pegin_tx(
    struct wally_psbt_input *input,
    const struct wally_tx *pegin_tx);

/**
 * Set the txout proof in an elements input.
 *
 * :param input: The input to update.
 * :param proof: The txout proof for this input.
 * :param proof_len: Length of ``proof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_txoutproof(
    struct wally_psbt_input *input,
    const unsigned char *proof,
    size_t proof_len);

/**
 * Set the genesis hash in an elements input.
 *
 * :param input: The input to update.
 * :param genesis_blockhash: The genesis hash for this input.
 * :param genesis_blockhash_len: Length of ``genesis_blockhash`` in bytes. Must be ``SHA256_LEN``.
 */
WALLY_CORE_API int wally_psbt_input_set_genesis_blockhash(
    struct wally_psbt_input *input,
    const unsigned char *genesis_blockhash,
    size_t genesis_blockhash_len);

/**
 * Set the claim script in an elements input.
 *
 * :param input: The input to update.
 * :param script: The claim script for this input.
 * :param script_len: Length of ``script`` in bytes.
 */
WALLY_CORE_API int wally_psbt_input_set_claim_script(
    struct wally_psbt_input *input,
    const unsigned char *script,
    size_t script_len);

/**
 * Set the blinding pubkey in an elements output.
 *
 * :param output: The output to update.
 * :param pub_key: The blinding pubkey for this output.
 * :param pub_key_len: Length of ``pub_key`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_blinding_pubkey(
    struct wally_psbt_output *output,
    const unsigned char *pub_key,
    size_t pub_key_len);

/**
 * Set the value commitment in an elements output.
 *
 * :param output: The output to update.
 * :param commitment: The value commitment for this output.
 * :param commitment_len: Length of ``commitment`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_value_commitment(
    struct wally_psbt_output *output,
    const unsigned char *commitment,
    size_t commitment_len);

/**
 * Set the value blinding factor in an elements output.
 *
 * :param output: The output to update.
 * :param vbf: The value blinding factor.
 * :param vbf_len: Length of ``vbf``. Must be ``BLINDING_FACTOR_LEN``.
 */
WALLY_CORE_API int wally_psbt_output_set_vbf(
    struct wally_psbt_output *output,
    const unsigned char *vbf,
    size_t vbf_len);

/**
 * Set the asset commitment in an elements output.
 *
 * :param output: The output to update.
 * :param commitment: The asset commitment for this output.
 * :param commitment_len: Length of ``commitment`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_asset_commitment(
    struct wally_psbt_output *output,
    const unsigned char *commitment,
    size_t commitment_len);

/**
 * Set the asset blinding factor in an elements output.
 *
 * :param output: The output to update.
 * :param abf: The asset blinding factor.
 * :param abf_len: Length of ``abf`` in bytes. Must be ``BLINDING_FACTOR_LEN``.
 */
WALLY_CORE_API int wally_psbt_output_set_abf(
    struct wally_psbt_output *output,
    const unsigned char *abf,
    size_t abf_len);

/**
 * Set the nonce commitment in an elements output.
 *
 * :param output: The output to update.
 * :param nonce: The commitment used to create the nonce (with the blinding key) for the range proof.
 * :param nonce_len: Size of ``nonce`` in bytes. Must be ``WALLY_TX_ASSET_CT_NONCE_LEN``.
 */
WALLY_CORE_API int wally_psbt_output_set_nonce(
    struct wally_psbt_output *output,
    const unsigned char *nonce,
    size_t nonce_len);

/**
 * Set the range proof in an elements output.
 *
 * :param output: The output to update.
 * :param proof: The range proof for this output.
 * :param proof_len: Length of ``proof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_rangeproof(
    struct wally_psbt_output *output,
    const unsigned char *proof,
    size_t proof_len);

/**
 * Set the surjection proof in an elements output.
 *
 * :param output: The output to update.
 * :param proof: The surjection proof for this output.
 * :param proof_len: Length of ``proof`` in bytes.
 */
WALLY_CORE_API int wally_psbt_output_set_surjectionproof(
    struct wally_psbt_output *output,
    const unsigned char *proof,
    size_t proof_len);
#endif /* SWIG */

#endif /* BUILD_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_PSBT_H */
