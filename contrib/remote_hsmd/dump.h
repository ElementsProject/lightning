#include <string>

std::string dump_hex(const void *vptr, size_t sz);
std::string dump_basepoints(const struct basepoints *bp);
std::string dump_bitcoin_txid(const struct bitcoin_txid *txid);
std::string dump_bitcoin_signature(const struct bitcoin_signature *sp);
std::string dump_secp256k1_ecdsa_signature(const secp256k1_ecdsa_signature *sp);
std::string dump_secp256k1_ecdsa_recoverable_signature(const secp256k1_ecdsa_recoverable_signature *sp);
std::string dump_node_id(const struct node_id *pp);
std::string dump_pubkey(const struct pubkey *kp);
std::string dump_unilateral_close_info(const struct unilateral_close_info *ip);
std::string dump_utxo(const struct utxo *in);
std::string dump_utxos(const struct utxo **utxos);
std::string dump_bitcoin_tx_output(const struct bitcoin_tx_output *op);
std::string dump_bitcoin_tx_outputs(const struct bitcoin_tx_output **outputs);
std::string dump_input_amounts(const struct amount_sat **ias);
std::string dump_wally_tx_witness_stack(const struct wally_tx_witness_stack *sp);
std::string dump_wally_tx_input(const struct wally_tx_input *in);
std::string dump_wally_tx_inputs(const struct wally_tx_input *inputs,
				 size_t num_inputs);
std::string dump_wally_tx_output(const struct wally_tx_output *out);
std::string dump_wally_tx_outputs(const struct wally_tx_output *outputs,
				  size_t num_outputs);
std::string dump_wally_tx(const struct wally_tx *wtx);
std::string dump_output_witscripts(const struct witscript **wp);
std::string dump_tx(const struct bitcoin_tx *tx);
