#ifndef LIBWALLY_CORE_TRANSACTION_INT_H
#define LIBWALLY_CORE_TRANSACTION_INT_H 1

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined(SWIG_JAVASCRIPT_BUILD)

#ifdef __cplusplus
extern "C" {
#endif

/* Input */
WALLY_CORE_API int wally_tx_input_get_txhash(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_input_get_script(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_input_get_script_len(const struct wally_tx_input *tx_input_in, size_t *written);
WALLY_CORE_API int wally_tx_input_get_witness(const struct wally_tx_input *tx_input_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_input_get_witness_len(const struct wally_tx_input *tx_input_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_input_get_index(const struct wally_tx_input *tx_input_in, size_t *written);
WALLY_CORE_API int wally_tx_input_get_sequence(const struct wally_tx_input *tx_input_in, size_t *written);

WALLY_CORE_API int wally_tx_input_set_txhash(struct wally_tx_input *tx_input, const unsigned char *txhash, size_t len);
WALLY_CORE_API int wally_tx_input_set_script(struct wally_tx_input *tx_input, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_tx_input_set_witness(struct wally_tx_input *tx_input, const struct wally_tx_witness_stack *witness);
WALLY_CORE_API int wally_tx_input_set_index(struct wally_tx_input *tx_input, uint32_t index);
WALLY_CORE_API int wally_tx_input_set_sequence(struct wally_tx_input *tx_input, uint32_t sequence);

#ifdef BUILD_ELEMENTS
WALLY_CORE_API int wally_tx_input_get_blinding_nonce(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_input_get_entropy(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_input_get_issuance_amount(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_input_get_issuance_amount_len(const struct wally_tx_input *tx_input_in, size_t *written);
WALLY_CORE_API int wally_tx_input_get_inflation_keys(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_input_get_inflation_keys_len(const struct wally_tx_input *tx_input_in, size_t *written);
WALLY_CORE_API int wally_tx_input_get_issuance_amount_rangeproof(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_input_get_issuance_amount_rangeproof_len(const struct wally_tx_input *tx_input_in, size_t *written);
WALLY_CORE_API int wally_tx_input_get_inflation_keys_rangeproof(const struct wally_tx_input *tx_input_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_input_get_inflation_keys_rangeproof_len(const struct wally_tx_input *tx_input_in, size_t *written);

WALLY_CORE_API int wally_tx_input_set_blinding_nonce(struct wally_tx_input *tx_input_in, const unsigned char *blinding_nonce, size_t blinding_nonce_len);
WALLY_CORE_API int wally_tx_input_set_entropy(struct wally_tx_input *tx_input_in, const unsigned char *entropy, size_t entropy_len);
WALLY_CORE_API int wally_tx_input_set_inflation_keys(struct wally_tx_input *tx_input_in, const unsigned char *inflation_keys, size_t inflation_keys_len);
WALLY_CORE_API int wally_tx_input_set_inflation_keys_rangeproof(struct wally_tx_input *tx_input_in, const unsigned char *inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len);
WALLY_CORE_API int wally_tx_input_set_issuance_amount(struct wally_tx_input *tx_input_in, const unsigned char *issuance_amount, size_t issuance_amount_len);
WALLY_CORE_API int wally_tx_input_set_issuance_amount_rangeproof(struct wally_tx_input *tx_input_in, const unsigned char *issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len);
#endif /* BUILD_ELEMENTS */

/* Output */
WALLY_CORE_API int wally_tx_output_get_script(const struct wally_tx_output *tx_output_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_output_get_script_len(const struct wally_tx_output *tx_output_in, size_t *written);
WALLY_CORE_API int wally_tx_output_get_satoshi(const struct wally_tx_output *tx_output_in, uint64_t *value_out);

WALLY_CORE_API int wally_tx_output_set_script(struct wally_tx_output *tx_output_in, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_tx_output_set_satoshi(struct wally_tx_output *tx_output_in, uint64_t satoshi);

#ifdef BUILD_ELEMENTS
WALLY_CORE_API int wally_tx_output_get_asset(const struct wally_tx_output *tx_output_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_output_get_asset_len(const struct wally_tx_output *tx_output_in, size_t *written);
WALLY_CORE_API int wally_tx_output_get_value(const struct wally_tx_output *tx_output_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_output_get_value_len(const struct wally_tx_output *tx_output_in, size_t *written);
WALLY_CORE_API int wally_tx_output_get_nonce(const struct wally_tx_output *tx_output_in, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_output_get_nonce_len(const struct wally_tx_output *tx_output_in, size_t *written);
WALLY_CORE_API int wally_tx_output_get_surjectionproof(const struct wally_tx_output *tx_output_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_output_get_surjectionproof_len(const struct wally_tx_output *tx_output_in, size_t *written);
WALLY_CORE_API int wally_tx_output_get_rangeproof(const struct wally_tx_output *tx_output_in, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_output_get_rangeproof_len(const struct wally_tx_output *tx_output_in, size_t *written);

WALLY_CORE_API int wally_tx_output_set_asset(struct wally_tx_output *tx_output_in, const unsigned char *asset, size_t asset_len);
WALLY_CORE_API int wally_tx_output_set_value(struct wally_tx_output *tx_output_in, const unsigned char *value, size_t value_len);
WALLY_CORE_API int wally_tx_output_set_nonce(struct wally_tx_output *tx_output_in, const unsigned char *nonce, size_t nonce_len);
WALLY_CORE_API int wally_tx_output_set_surjectionproof(struct wally_tx_output *tx_output_in, const unsigned char *surjectionproof, size_t surjectionproof_len);
WALLY_CORE_API int wally_tx_output_set_rangeproof(struct wally_tx_output *tx_output_in, const unsigned char *rangeproof, size_t rangeproof_len);
#endif /* BUILD_ELEMENTS */

/* Transaction */
WALLY_CORE_API int wally_tx_get_version(const struct wally_tx *tx_in, size_t *written);
WALLY_CORE_API int wally_tx_get_locktime(const struct wally_tx *tx_in, size_t *written);
WALLY_CORE_API int wally_tx_get_num_inputs(const struct wally_tx *tx_in, size_t *written);
WALLY_CORE_API int wally_tx_get_num_outputs(const struct wally_tx *tx_in, size_t *written);

/* Transaction Inputs */
WALLY_CORE_API int wally_tx_get_input_txhash(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_get_input_script(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_input_script_len(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_input_witness(const struct wally_tx *tx_in, size_t index, size_t wit_index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_input_witness_len(const struct wally_tx *tx_in, size_t index, size_t wit_index, size_t *written);
WALLY_CORE_API int wally_tx_get_input_index(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_input_sequence(const struct wally_tx *tx_in, size_t index, size_t *written);

WALLY_CORE_API int wally_tx_set_input_index(const struct wally_tx *tx_in, size_t index, uint32_t index_in);
WALLY_CORE_API int wally_tx_set_input_sequence(const struct wally_tx *tx_in, size_t index, uint32_t sequence);
WALLY_CORE_API int wally_tx_set_input_txhash(const struct wally_tx *tx_in, size_t index, const unsigned char *txhash, size_t len);

#ifdef BUILD_ELEMENTS
WALLY_CORE_API int wally_tx_get_input_blinding_nonce(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_get_input_entropy(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_get_input_issuance_amount(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_input_issuance_amount_len(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_input_inflation_keys(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_input_inflation_keys_len(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_input_issuance_amount_rangeproof(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_input_issuance_amount_rangeproof_len(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_input_inflation_keys_rangeproof(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_input_inflation_keys_rangeproof_len(const struct wally_tx *tx_in, size_t index, size_t *written);

WALLY_CORE_API int wally_tx_set_input_blinding_nonce(const struct wally_tx *tx_in, size_t index, const unsigned char *blinding_nonce, size_t blinding_nonce_len);
WALLY_CORE_API int wally_tx_set_input_entropy(const struct wally_tx *tx_in, size_t index, const unsigned char *entropy, size_t entropy_len);
WALLY_CORE_API int wally_tx_set_input_inflation_keys(const struct wally_tx *tx_in, size_t index, const unsigned char *inflation_keys, size_t inflation_keys_len);
WALLY_CORE_API int wally_tx_set_input_inflation_keys_rangeproof(const struct wally_tx *tx_in, size_t index, const unsigned char *inflation_keys_rangeproof, size_t inflation_keys_rangeproof_len);
WALLY_CORE_API int wally_tx_set_input_issuance_amount(const struct wally_tx *tx_in, size_t index, const unsigned char *issuance_amount, size_t issuance_amount_len);
WALLY_CORE_API int wally_tx_set_input_issuance_amount_rangeproof(const struct wally_tx *tx_in, size_t index, const unsigned char *issuance_amount_rangeproof, size_t issuance_amount_rangeproof_len);
#endif /* BUILD_ELEMENTS */

/* Transaction Outputs */
WALLY_CORE_API int wally_tx_get_output_script(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_output_script_len(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_output_satoshi(const struct wally_tx *tx_in, size_t index, uint64_t *value_out);

WALLY_CORE_API int wally_tx_set_output_script(const struct wally_tx *tx_in, size_t index, const unsigned char *script, size_t script_len);
WALLY_CORE_API int wally_tx_set_output_satoshi(const struct wally_tx *tx_in, size_t index, uint64_t satoshi);

#ifdef BUILD_ELEMENTS
WALLY_CORE_API int wally_tx_get_output_asset(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_get_output_value(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_output_value_len(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_output_nonce(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len);
WALLY_CORE_API int wally_tx_get_output_surjectionproof(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_output_surjectionproof_len(const struct wally_tx *tx_in, size_t index, size_t *written);
WALLY_CORE_API int wally_tx_get_output_rangeproof(const struct wally_tx *tx_in, size_t index, unsigned char *bytes_out, size_t len, size_t *written);
WALLY_CORE_API int wally_tx_get_output_rangeproof_len(const struct wally_tx *tx_in, size_t index, size_t *written);

WALLY_CORE_API int wally_tx_set_output_asset(const struct wally_tx *tx_in, size_t index, const unsigned char *asset, size_t asset_len);
WALLY_CORE_API int wally_tx_set_output_value(const struct wally_tx *tx_in, size_t index, const unsigned char *value, size_t value_len);
WALLY_CORE_API int wally_tx_set_output_nonce(const struct wally_tx *tx_in, size_t index, const unsigned char *nonce, size_t nonce_len);
WALLY_CORE_API int wally_tx_set_output_surjectionproof(const struct wally_tx *tx_in, size_t index, const unsigned char *surjectionproof, size_t surjectionproof_len);
WALLY_CORE_API int wally_tx_set_output_rangeproof(const struct wally_tx *tx_in, size_t index, const unsigned char *rangeproof, size_t rangeproof_len);
#endif
#ifdef __cplusplus
}
#endif

#endif /* SWIG/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD/SWIG_JAVASCRIPT_BUILD */

#endif /* LIBWALLY_CORE_TRANSACTION_INT_H */
