#ifdef __cplusplus
extern "C" {
#endif

#include <ccan/short_types/short_types.h>

enum proxy_status {
	/* SUCCESS */
	PROXY_OK = 0,

	/* TRANSIENT */
	PROXY_TIMEOUT = 32,
	PROXY_UNAVAILABLE = 33,
	PROXY_CANCELLED = 34,

	/* PERMANENT */
	PROXY_INVALID_ARGUMENT = 100,
	PROXY_INTERNAL_ERROR = 200,
};
typedef enum proxy_status proxy_stat;

#define PROXY_SUCCESS(rv)	((rv) < 32)
#define PROXY_TRANSIENT(rv)	((rv) >= 32 && (rv) < 100)
#define PROXY_PERMANENT(rv)	((rv) >= 100)

char const *proxy_last_message(void);

void proxy_setup(void);

proxy_stat proxy_init_hsm(
	struct bip32_key_version *bip32_key_version,
	struct chainparams const *chainparams,
	bool coldstart,
	struct secret *hsm_secret,
	struct node_id *o_node_id,
	struct ext_key *o_ext_pub_key);

proxy_stat proxy_handle_ecdh(
	const struct pubkey *point,
	struct secret *o_ss);

proxy_stat proxy_handle_pass_client_hsmfd(
	struct node_id *peer_id,
	u64 dbid,
	u64 capabilities);

proxy_stat proxy_handle_new_channel(
	struct node_id *peer_id,
	u64 dbid);

proxy_stat proxy_handle_ready_channel(
	struct node_id *peer_id,
	u64 dbid,
	bool is_outbound,
	struct amount_sat *channel_value,
	struct amount_msat *push_value,
	struct bitcoin_txid *funding_txid,
	u16 funding_txout,
	u16 local_to_self_delay,
	u8 *local_shutdown_script,
	struct basepoints *remote_basepoints,
	struct pubkey *remote_funding_pubkey,
	u16 remote_to_self_delay,
	u8 *remote_shutdown_script,
	bool option_static_remotekey);

proxy_stat proxy_handle_sign_withdrawal_tx(
	struct node_id *peer_id, u64 dbid,
	struct amount_sat *satoshi_out,
	struct amount_sat *change_out,
	u32 change_keyindex,
	struct bitcoin_tx_output **outputs,
	struct utxo **utxos,
	struct bitcoin_tx *tx,
	u8 ****o_wits);

proxy_stat proxy_handle_sign_remote_commitment_tx(
	struct bitcoin_tx *tx,
	const struct pubkey *remote_funding_pubkey,
	struct node_id *peer_id,
	u64 dbid,
	const struct pubkey *remote_per_commit,
	bool option_static_remotekey,
	struct bitcoin_signature *o_sig);

proxy_stat proxy_handle_get_per_commitment_point(
	struct node_id *peer_id,
	u64 dbid,
	u64 n,
	struct pubkey *o_per_commitment_point,
	struct secret **o_old_secret);

proxy_stat proxy_handle_sign_invoice(
	u5 *u5bytes,
	u8 *hrpu8,
	secp256k1_ecdsa_recoverable_signature *o_sig);

proxy_stat proxy_handle_sign_message(
	u8 *msg,
	secp256k1_ecdsa_recoverable_signature *o_sig);

proxy_stat proxy_handle_get_channel_basepoints(
	struct node_id *peer_id,
	u64 dbid,
	struct basepoints *o_basepoints,
	struct pubkey *o_funding_pubkey);

proxy_stat proxy_handle_sign_mutual_close_tx(
	struct bitcoin_tx *tx,
	const struct pubkey *remote_funding_pubkey,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig);

proxy_stat proxy_handle_sign_commitment_tx(
	struct bitcoin_tx *tx,
	const struct pubkey *remote_funding_pubkey,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig);

proxy_stat proxy_handle_cannouncement_sig(
	struct node_id *peer_id,
	u64 dbid,
	u8 *channel_announcement,
	secp256k1_ecdsa_signature *o_node_sig,
	secp256k1_ecdsa_signature *o_bitcoin_sig);

proxy_stat proxy_handle_channel_update_sig(
	u8 *channel_update,
	secp256k1_ecdsa_signature *o_sig);

proxy_stat proxy_handle_sign_local_htlc_tx(
	struct bitcoin_tx *tx,
	u64 commit_num,
	u8 *wscript,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig);

proxy_stat proxy_handle_sign_remote_htlc_tx(
	struct bitcoin_tx *tx,
	u8 *wscript,
	const struct pubkey *remote_per_commit_point,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig);

proxy_stat proxy_handle_sign_delayed_payment_to_us(
	struct bitcoin_tx *tx,
	u64 commit_num,
	u8 *wscript,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig);

proxy_stat proxy_handle_sign_remote_htlc_to_us(
	struct bitcoin_tx *tx,
	u8 *wscript,
	const struct pubkey *remote_per_commit_point,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig);

proxy_stat proxy_handle_sign_penalty_to_us(
	struct bitcoin_tx *tx,
	struct secret *revocation_secret,
	u8 *wscript,
	struct node_id *peer_id,
	u64 dbid,
	struct bitcoin_signature *o_sig);

proxy_stat proxy_handle_check_future_secret(
	struct node_id *peer_id,
	u64 dbid,
	u64 n,
	struct secret *suggested,
	bool *o_correct);

proxy_stat proxy_handle_sign_node_announcement(
	u8 *node_announcement,
	secp256k1_ecdsa_signature *o_sig);

// FIXME - For debugging, remove for production.
void print_tx(char const *tag, struct bitcoin_tx const *tx);

#ifdef __cplusplus
} /* extern C */
#endif
