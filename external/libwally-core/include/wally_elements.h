#ifndef LIBWALLY_CORE_ELEMENTS_H
#define LIBWALLY_CORE_ELEMENTS_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILD_ELEMENTS

#define ASSET_TAG_LEN 32 /** Length of an Asset Tag */

#define BLINDING_FACTOR_LEN 32 /** Length of a Blinding Factor (or blinder) */

#define ASSET_GENERATOR_LEN 33 /** Length of an Asset Generator */

#define ASSET_COMMITMENT_LEN 33 /** Length of an Asset Value Commitment */

#define ASSET_RANGEPROOF_MAX_LEN 5134 /** Maximum length of an Asset Range Proof */

/**
 * Create a blinded Asset Generator from an Asset Tag and Asset Blinding Factor.
 *
 * :param asset: Asset Tag to create a blinding generator for.
 * :param asset_len: Length of ``asset`` in bytes. Must be ``ASSET_TAG_LEN``.
 * :param abf: Asset Blinding Factor (Random entropy to blind with).
 * :param abf_len: Length of ``abf`` in bytes. Must be ``BLINDING_FACTOR_LEN``.
 * :param bytes_out: Destination for the resulting Asset Generator.
 * :param len: The length of ``bytes_out`` in bytes. Must be ``ASSET_GENERATOR_LEN``.
 */
WALLY_CORE_API int wally_asset_generator_from_bytes(
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Generate the final value blinding factor required for blinding a confidential transaction.
 *
 * :param values: Array of transaction input values in satoshi
 * :param values_len: Length of ``values``, also the number of elements in all three of the input arrays, which is equal
 *|     to ``num_inputs`` plus the number of outputs.
 * :param num_inputs: Number of elements in the input arrays that represent transaction inputs. The number of outputs is
 *|     implicitly ``values_len`` - ``num_inputs``.
 * :param abf:  Array of bytes representing ``values_len`` asset blinding factors.
 * :param abf_len: Length of ``abf`` in bytes. Must be ``values_len`` * ``BLINDING_FACTOR_LEN``.
 * :param vbf: Array of bytes representing (``values_len`` - 1) value blinding factors.
 * :param vbf_len: Length of ``vbf`` in bytes. Must be (``values_len`` - 1) * ``BLINDING_FACTOR_LEN``.
 * :param bytes_out: Buffer to receive the final value blinding factor.
 * :param len: Length of ``bytes_out``. Must be ``BLINDING_FACTOR_LEN``.
 */
WALLY_CORE_API int wally_asset_final_vbf(
    const uint64_t *values,
    size_t values_len,
    size_t num_inputs,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *vbf,
    size_t vbf_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Calculate the value commitment for a transaction output.
 *
 * :param value: Output value in satoshi.
 * :param vbf: Value Blinding Factor.
 * :param vbf_len: Length of ``vbf``. Must be ``BLINDING_FACTOR_LEN``.
 * :param generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param generator_len: Length of ``generator``. Must be ``ASSET_GENERATOR_LEN``.
 * :param bytes_out: Buffer to receive value commitment.
 * :param len: Length of ``bytes_out``. Must be ``ASSET_COMMITMENT_LEN``.
 */
WALLY_CORE_API int wally_asset_value_commitment(
    uint64_t value,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *bytes_out,
    size_t len);

/*
 * As per wally_asset_rangeproof with a user provided nonce.
 */
WALLY_CORE_API int wally_asset_rangeproof_with_nonce(
    uint64_t value,
    const unsigned char *nonce_hash,
    size_t nonce_hash_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *extra,
    size_t extra_len,
    const unsigned char *generator,
    size_t generator_len,
    uint64_t min_value,
    int exp,
    int min_bits,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Generate a rangeproof for a transaction output.
 *
 * :param value: Value of the output in satoshi.
 * :param pub_key: Public blinding key for the output. See `wally_confidential_addr_to_ec_public_key`.
 * :param pub_key_len: Length of ``pub_key``. Must be ``EC_PUBLIC_KEY_LEN``
 * :param priv_key: Pivate ephemeral key. Should be randomly generated for each output.
 * :param priv_key_length: Length of ``priv_key``.
 * :param asset: Asset id of output.
 * :param asset_len: Length of ``asset``. Must be ``ASSET_TAG_LEN``.
 * :param abf: Asset blinding factor. Randomly generated for each output.
 * :param abf_len: Length of ``abf``. Must be ``BLINDING_FACTOR_LEN``.
 * :param vbf: Value blinding factor. Randomly generated for each output except the last, which is generate by calling
 *|     `wally_asset_final_vbf`.
 * :param vbf_len: Length of ``vbf``. Must be ``BLINDING_FACTOR_LEN``.
 * :param commitment: Value commitment from `wally_asset_value_commitment`.
 * :param commitment_len: Length of ``commitment``. Must be ``ASSET_COMMITMENT_LEN``.
 * :param extra: Set this to the script pubkey of the output.
 * :param extra_len: Length of ``extra``, i.e. script pubkey.
 * :param generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param generator_len: Length of ``generator`. Must be ``ASSET_GENERATOR_LEN``.
 * :param min_value: Recommended value 1.
 * :param exp: Exponent value. -1 >= ``exp`` >= 18. Recommended value 0.
 * :param min_bits: 0 >= min_bits >= 64. Recommended value 52.
 * :param bytes_out: Buffer to receive rangeproof.
 * :param len: Length of ``bytes_out``. See ``ASSET_RANGEPROOF_MAX_LEN``.
 * :param written: Number of bytes actually written to ``bytes_out``.
 */
WALLY_CORE_API int wally_asset_rangeproof(
    uint64_t value,
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *extra,
    size_t extra_len,
    const unsigned char *generator,
    size_t generator_len,
    uint64_t min_value,
    int exp,
    int min_bits,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Return the required buffer size for receiving a surjection proof
 *
 * :param num_inputs: Number of transaction inputs.
 * :param written: Destination for the surjection proof size.
 */
WALLY_CORE_API int wally_asset_surjectionproof_size(
    size_t num_inputs,
    size_t *written);

/**
 * Generate a surjection proof for a transaction output
 *
 * :param output_asset: asset id for the output.
 * :param output_asset_len: Length of ``asset``. Must be ``ASSET_TAG_LEN``.
 * :param output_abf: Asset blinding factor for the output. Generated randomly for each output.
 * :param output_abf_len: Length of ``output_abf``. Must be ``BLINDING_FACTOR_LEN``.
 * :param output_generator: Asset generator from `wally_asset_generator_from_bytes`.
 * :param output_generator_len: Length of ``output_generator`. Must be ``ASSET_GENERATOR_LEN``.
 * :param bytes: Must be generated randomly for each output.
 * :param bytes_len: Length of ``bytes``. Must be 32.
 * :param asset: Array of input asset tags.
 * :param asset_len: Length of ``asset`. Must be ``ASSET_TAG_LEN`` * number of inputs.
 * :param abf: Array of asset blinding factors from the transaction inputs.
 * :param abf_len: Length of ``abf``. Must be ``BLINDING_FACTOR_LEN`` * number of inputs.
 * :param generator: Array of asset generators from transaction inputs.
 * :param generator_len: Length of ``generator``. Must be ``ASSET_GENERATOR_LEN`` * number of inputs.
 * :param bytes_out: Buffer to receive surjection proof.
 * :param bytes_out_len: Length of ``bytes_out``. See `wally_asset_surjectionproof_size`.
 * :param written: Number of bytes actually written to ``bytes_out``.
 */
WALLY_CORE_API int wally_asset_surjectionproof(
    const unsigned char *output_asset,
    size_t output_asset_len,
    const unsigned char *output_abf,
    size_t output_abf_len,
    const unsigned char *output_generator,
    size_t output_generator_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

/**
 * Unblind a confidential transaction output.
 *
 * :param nonce_hash: SHA-256 hash of the generated nonce.
 * :param nonce_hash_len: Length of ``nonce_hash``. Must be ``SHA256_LEN``.
 * :param proof: Rangeproof from :c:func:`wally_tx_get_output_rangeproof`.
 * :param proof_len: Length of ``proof``.
 * :param commitment: Value commitment from :c:func:`wally_tx_get_output_value`.
 * :param commitment_len: Length of ``commitment``.
 * :param extra: Script pubkey from :c:func:`wally_tx_get_output_script`.
 * :param extra_len: Length of ``extra``.
 * :param generator: Asset generator from :c:func:`wally_tx_get_output_asset`.
 * :param generator_len: Length of ``generator``. Must be ``ASSET_GENERATOR_LEN``.
 * :param asset_out: Buffer to receive unblinded asset id.
 * :param asset_out_len: Length of ``asset_out``. Must be ``ASSET_TAG_LEN``.
 * :param abf_out: Buffer to receive asset blinding factor.
 * :param abf_out_len: Length of ``abf_out``. Must be ``BLINDING_FACTOR_LEN``.
 * :param vbf_out: Buffer to receive asset blinding factor.
 * :param vbf_out_len: Length of ``vbf_out``. Must be ``BLINDING_FACTOR_LEN``.
 * :param value_out: Destination for unblinded transaction output value.
 */
WALLY_CORE_API int wally_asset_unblind_with_nonce(
    const unsigned char *nonce_hash,
    size_t nonce_hash_len,
    const unsigned char *proof,
    size_t proof_len,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *extra,
    size_t extra_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *asset_out,
    size_t asset_out_len,
    unsigned char *abf_out,
    size_t abf_out_len,
    unsigned char *vbf_out,
    size_t vbf_out_len,
    uint64_t *value_out);

/**
 * Unblind a confidential transaction output.
 *
 * :param pub_key: From :c:func:`wally_tx_get_output_nonce`.
 * :param pub_key_len: Length of ``pub_key``. Must be ``EC_PUBLIC_KEY_LEN``.
 * :param priv_key: Private blinding key corresponding to public blinding key used to generate destination address. See
 *|     :c:func:`wally_asset_blinding_key_to_ec_private_key`.
 * :param proof: Rangeproof from :c:func:`wally_tx_get_output_rangeproof`.
 * :param proof_len: Length of ``proof``.
 * :param commitment: Value commitment from :c:func:`wally_tx_get_output_value`.
 * :param commitment_len: Length of ``commitment``.
 * :param extra: Script pubkey from :c:func:`wally_tx_get_output_script`.
 * :param extra_len: Length of ``extra``.
 * :param generator: Asset generator from :c:func:`wally_tx_get_output_asset`.
 * :param generator_len: Length of ``generator``. Must be ``ASSET_GENERATOR_LEN``.
 * :param asset_out: Buffer to receive unblinded asset id.
 * :param asset_out_len: Length of ``asset_out``. Must be ``ASSET_TAG_LEN``.
 * :param abf_out: Buffer to receive asset blinding factor.
 * :param abf_out_len: Length of ``abf_out``. Must be ``BLINDING_FACTOR_LEN``.
 * :param vbf_out: Buffer to receive asset blinding factor.
 * :param vbf_out_len: Length of ``vbf_out``. Must be ``BLINDING_FACTOR_LEN``.
 * :param value_out: Destination for unblinded transaction output value.
 */
WALLY_CORE_API int wally_asset_unblind(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *proof,
    size_t proof_len,
    const unsigned char *commitment,
    size_t commitment_len,
    const unsigned char *extra,
    size_t extra_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *asset_out,
    size_t asset_out_len,
    unsigned char *abf_out,
    size_t abf_out_len,
    unsigned char *vbf_out,
    size_t vbf_out_len,
    uint64_t *value_out);

/**
 * Generate a master blinding key from a seed as specified in SLIP-0077.
 *
 * :param bytes: Seed value. See :c:func:`bip39_mnemonic_to_seed`.
 * :param bytes_len: Length of ``seed``. Must be one of ``BIP32_ENTROPY_LEN_128``, ``BIP32_ENTROPY_LEN_256`` or
 *|     ``BIP32_ENTROPY_LEN_512``.
 * :param bytes_out: Buffer to receive master blinding key. The master blinding key can be used to generate blinding
 *|     keys for specific outputs by passing it to `wally_asset_blinding_key_to_ec_private_key`.
 * :param len: Length of ``bytes_out``. Must be ``HMAC_SHA512_LEN``.
 */
WALLY_CORE_API int wally_asset_blinding_key_from_seed(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Generate a blinding key for a script pubkey.
 *
 * :param bytes: Master blinding key from `wally_asset_blinding_key_from_seed`.
 * :param bytes_len: Length of ``bytes``. Must be ``HMAC_SHA512_LEN``.
 * :param script: The script pubkey for the confidential output address.
 * :param script_len: Length of ``script``.
 * :param bytes_out: Buffer to receive blinding key.
 * :param len: Length of ``bytes_out``. Must be ``EC_PRIVATE_KEY_LEN``.
 */
WALLY_CORE_API int wally_asset_blinding_key_to_ec_private_key(
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *script,
    size_t script_len,
    unsigned char *bytes_out,
    size_t len);

/**
 * Calculate the size in bytes of the whitelist proof.
 *
 * :param num_keys: The number of offline/online keys.
 * :param written: Destination for the number of bytes needed for the proof.
 */
WALLY_CORE_API int wally_asset_pak_whitelistproof_size(
    size_t num_keys,
    size_t *written);

/**
 * Generate the whitelist proof for the pegout script.
 *
 * :param online_keys: The list of online keys.
 * :param online_keys_len: Length of ``online_keys_len`` in bytes. Must be a multiple of ``EC_PUBLIC_KEY_LEN``.
 * :param offline_keys: The list of offline keys.
 * :param offline_keys_len: Length of ``offline_keys_len`` in bytes. Must be a multiple of ``EC_PUBLIC_KEY_LEN``.
 * :param key_index: The index in the PAK list of the key signing this whitelist proof
 * :param sub_pubkey: The key to be whitelisted.
 * :param sub_pubkey_len: Length of ``sub_pubkey`` in bytes. Must be ``EC_PUBLIC_KEY_LEN``.
 * :param online_priv_key: The secret key to the signer's online pubkey.
 * :param online_priv_key_len: Length of ``online_priv_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param summed_key: The secret key to the sum of (whitelisted key, signer's offline pubkey).
 * :param summed_key_len: Length of ``summed_key`` in bytes. Must be ``EC_PRIVATE_KEY_LEN``.
 * :param bytes_out: Destination for the resulting whitelist proof.
 * :param len: Length of ``bytes_out`` in bytes.
 * :param written: Number of bytes actually written to ``bytes_out``.
 */
WALLY_CORE_API int wally_asset_pak_whitelistproof(
    const unsigned char *online_keys,
    size_t online_keys_len,
    const unsigned char *offline_keys,
    size_t offline_keys_len,
    size_t key_index,
    const unsigned char *sub_pubkey,
    size_t sub_pubkey_len,
    const unsigned char *online_priv_key,
    size_t online_priv_key_len,
    const unsigned char *summed_key,
    size_t summed_key_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);

#endif /* BUILD_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_ELEMENTS_H */
