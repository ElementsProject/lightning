#ifndef LIGHTNING_CONTRIB_REMOTE_HSMD_DUMP_H
#define LIGHTNING_CONTRIB_REMOTE_HSMD_DUMP_H

extern "C" {
#include <ccan/short_types/short_types.h>
#include <secp256k1_recovery.h>
}
#include <string>

std::string dump_optional_wallet_index(u32 *optional_wallet_index);
std::string dump_hex(const void *vptr, size_t sz);
std::string dump_basepoints(const struct basepoints *bp);
std::string dump_bitcoin_txid(const struct bitcoin_txid *txid);
std::string dump_bitcoin_signature(const struct bitcoin_signature *sp);
std::string dump_htlc_signatures(const struct bitcoin_signature *sps);
std::string dump_secp256k1_ecdsa_signature(const secp256k1_ecdsa_signature *sp);
std::string dump_secp256k1_ecdsa_recoverable_signature(const secp256k1_ecdsa_recoverable_signature *sp);
std::string dump_secret(const struct secret *sp);
std::string dump_node_id(const struct node_id *pp);
std::string dump_pubkey(const struct pubkey *kp);
std::string dump_ext_pubkey(const struct ext_key *xp);
std::string dump_witnesses(const u8 ***wp);
std::string dump_unilateral_close_info(const struct unilateral_close_info *ip);
std::string dump_utxo(const struct utxo *in);
std::string dump_utxos(const struct utxo **utxos);
std::string dump_bitcoin_tx_output(const struct bitcoin_tx_output *op);
std::string dump_bitcoin_tx_outputs(const struct bitcoin_tx_output **outputs);
std::string dump_wally_tx_witness_stack(const struct wally_tx_witness_stack *sp);
std::string dump_wally_keypath_map(const struct wally_map *mp);
std::string dump_wally_partial_sigs_map(const struct wally_map *mp);
std::string dump_wally_unknowns_map(const struct wally_map *mp);
std::string dump_wally_tx_input(const struct wally_tx_input *in);
std::string dump_wally_tx_inputs(const struct wally_tx_input *inputs,
				 size_t num_inputs);
std::string dump_wally_tx_output(const struct wally_tx_output *out);
std::string dump_wally_tx_outputs(const struct wally_tx_output *outputs,
				  size_t num_outputs);
std::string dump_wally_tx(const struct wally_tx *wtx);
std::string dump_wally_psbt(const struct wally_psbt *psbt);
std::string dump_tx(const struct bitcoin_tx *tx);
std::string dump_rhashes(const struct sha256 *rhashes, size_t num_rhashes);
std::string dump_htlc(const struct simple_htlc *htlc);
std::string dump_htlcs(const struct simple_htlc **htlc, size_t num_htlc);

// needed for formatting txid
void reverse_bytes(u8 *arr, size_t len);

#endif /* LIGHTNING_CONTRIB_REMOTE_HSMD_DUMP_H */
