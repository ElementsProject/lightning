#ifndef LIBWALLY_CORE_PSBT_INT_H
#define LIBWALLY_CORE_PSBT_INT_H 1

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined(SWIG_JAVASCRIPT_BUILD)

#ifdef __cplusplus
extern "C" {
#endif

/* PSBT */

WALLY_CORE_API int wally_psbt_get_global_tx_alloc(const struct wally_psbt *psbt, struct wally_tx **output);
WALLY_CORE_API int wally_psbt_get_version(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_num_inputs(const struct wally_psbt *psbt, size_t *written);
WALLY_CORE_API int wally_psbt_get_num_outputs(const struct wally_psbt *psbt, size_t *written);

/* Inputs */
WALLY_CORE_API int wally_psbt_get_input_utxo_alloc(const struct wally_psbt *psbt, size_t index, struct wally_tx **output);
WALLY_CORE_API int wally_psbt_get_input_witness_utxo_alloc(const struct wally_psbt *psbt, size_t index, struct wally_tx_output **output);
WALLY_CORE_API int wally_psbt_get_input_redeem_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_redeem_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_witness_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_witness_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_final_scriptsig(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_final_scriptsig_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_final_witness_alloc(const struct wally_psbt *psbt, size_t index, struct wally_tx_witness_stack **output);
WALLY_CORE_API int wally_psbt_get_input_keypaths_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_input_keypath(const struct wally_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_keypath(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_keypath_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_signatures_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_input_signature(const struct wally_psbt *psbt, size_t index, const unsigned char *pub_key, size_t pub_key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_signature(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_signature_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_unknowns_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_input_unknown(const struct wally_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_unknown(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_unknown_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_sighash(const struct wally_psbt *psbt, size_t index, size_t *written);

WALLY_CORE_API int wally_psbt_set_input_utxo(struct wally_psbt *psbt, size_t index, const struct wally_tx *utxo);
WALLY_CORE_API int wally_psbt_set_input_witness_utxo(struct wally_psbt *psbt, size_t index, const struct wally_tx_output *witness_utxo);
WALLY_CORE_API int wally_psbt_set_input_redeem_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_input_witness_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_input_final_scriptsig(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_input_final_witness(struct wally_psbt *psbt, size_t index, const struct wally_tx_witness_stack *final_witness);
WALLY_CORE_API int wally_psbt_set_input_keypaths(struct wally_psbt *psbt, size_t index, const struct wally_map *map_in);
WALLY_CORE_API int wally_psbt_set_input_signatures(struct wally_psbt *psbt, size_t index, const struct wally_map *map_in);
WALLY_CORE_API int wally_psbt_set_input_unknowns(struct wally_psbt *psbt, size_t index, const struct wally_map *map_in);
WALLY_CORE_API int wally_psbt_set_input_sighash(struct wally_psbt *psbt, size_t index, uint32_t sighash);

#ifdef BUILD_ELEMENTS
WALLY_CORE_API int wally_psbt_get_input_value(const struct wally_psbt *psbt, size_t index, uint64_t *value_out);
WALLY_CORE_API int wally_psbt_has_input_value(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_vbf(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_vbf_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_asset(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_asset_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_abf(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_abf_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_pegin_tx_alloc(const struct wally_psbt *psbt, size_t index, struct wally_tx **output);
WALLY_CORE_API int wally_psbt_get_input_txoutproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_txoutproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_genesis_blockhash(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_genesis_blockhash_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_claim_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_input_claim_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);

WALLY_CORE_API int wally_psbt_set_input_value(struct wally_psbt *psbt, size_t index, uint64_t value);
WALLY_CORE_API int wally_psbt_clear_input_value(struct wally_psbt *psbt, size_t index);
WALLY_CORE_API int wally_psbt_set_input_vbf(struct wally_psbt *psbt, size_t index, const unsigned char *vbf, size_t vbf_len);
WALLY_CORE_API int wally_psbt_set_input_asset(struct wally_psbt *psbt, size_t index, const unsigned char *asset, size_t asset_len);
WALLY_CORE_API int wally_psbt_set_input_abf(struct wally_psbt *psbt, size_t index, const unsigned char *abf, size_t abf_len);
WALLY_CORE_API int wally_psbt_set_input_pegin_tx(struct wally_psbt *psbt, size_t index, const struct wally_tx *pegin_tx);
WALLY_CORE_API int wally_psbt_set_input_txoutproof(struct wally_psbt *psbt, size_t index, const unsigned char *proof, size_t proof_len);
WALLY_CORE_API int wally_psbt_set_input_genesis_blockhash(struct wally_psbt *psbt, size_t index, const unsigned char *genesis_blockhash, size_t genesis_blockhash_len);
WALLY_CORE_API int wally_psbt_set_input_claim_script(struct wally_psbt *psbt, size_t index, const unsigned char *script, size_t script_len);
#endif /* BUILD_ELEMENTS */

/* Outputs */
WALLY_CORE_API int wally_psbt_get_output_redeem_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_redeem_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_witness_script(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_witness_script_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_keypaths_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_output_keypath(const struct wally_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_keypath(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_keypath_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_unknowns_size(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_find_output_unknown(const struct wally_psbt *psbt, size_t index, const unsigned char *key, size_t key_len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_unknown(const struct wally_psbt *psbt, size_t index, size_t subindex, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_unknown_len(const struct wally_psbt *psbt, size_t index, size_t subindex, size_t *written);

WALLY_CORE_API int wally_psbt_set_output_redeem_script(struct wally_psbt *psbt, size_t index,  const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_output_witness_script(struct wally_psbt *psbt, size_t index,  const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_psbt_set_output_keypaths(struct wally_psbt *psbt, size_t index,  const struct wally_map *map_in);
WALLY_CORE_API int wally_psbt_set_output_unknowns(struct wally_psbt *psbt, size_t index,  const struct wally_map *map_in);

#ifdef BUILD_ELEMENTS
WALLY_CORE_API int wally_psbt_get_output_blinding_pubkey(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_blinding_pubkey_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_value_commitment(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_value_commitment_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_vbf(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_vbf_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_asset_commitment(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_asset_commitment_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_abf(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_abf_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_nonce(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_nonce_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_rangeproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_rangeproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_surjectionproof(const struct wally_psbt *psbt, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_psbt_get_output_surjectionproof_len(const struct wally_psbt *psbt, size_t index, size_t *written);

WALLY_CORE_API int wally_psbt_set_output_blinding_pubkey(struct wally_psbt *psbt, size_t index, const unsigned char *pub_key, size_t pub_key_len);
WALLY_CORE_API int wally_psbt_set_output_value_commitment(struct wally_psbt *psbt, size_t index, const unsigned char *commitment, size_t commitment_len);
WALLY_CORE_API int wally_psbt_set_output_vbf(struct wally_psbt *psbt, size_t index, const unsigned char *vbf, size_t vbf_len);
WALLY_CORE_API int wally_psbt_set_output_asset_commitment(struct wally_psbt *psbt, size_t index, const unsigned char *commitment, size_t commitment_len);
WALLY_CORE_API int wally_psbt_set_output_abf(struct wally_psbt *psbt, size_t index, const unsigned char *abf, size_t abf_len);
WALLY_CORE_API int wally_psbt_set_output_nonce(struct wally_psbt *psbt, size_t index, const unsigned char *nonce, size_t nonce_len);
WALLY_CORE_API int wally_psbt_set_output_rangeproof(struct wally_psbt *psbt, size_t index, const unsigned char *proof, size_t proof_len);
WALLY_CORE_API int wally_psbt_set_output_surjectionproof(struct wally_psbt *psbt, size_t index, const unsigned char *proof, size_t proof_len);
#endif /* BUILD_ELEMENTS */

#ifdef __cplusplus
}
#endif

#endif /* SWIG/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD/SWIG_JAVASCRIPT_BUILD */

#endif /* LIBWALLY_CORE_PSBT_INT_H */
