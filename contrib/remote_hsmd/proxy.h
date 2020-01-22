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
	struct secret *hsm_encryption_key,
	struct privkey *privkey,
	struct secret *seed,
	struct secrets *secrets,
	struct sha256 *shaseed,
	struct secret *hsm_secret,
	struct node_id *o_node_id);

proxy_stat proxy_handle_ecdh(
	struct pubkey *point,
	struct secret *o_ss);

proxy_stat proxy_handle_sign_withdrawal_tx(
	struct node_id *peer_id, u64 dbid,
	struct amount_sat *satoshi_out,
	struct amount_sat *change_out,
	u32 change_keyindex,
	struct bitcoin_tx_output **outputs,
	struct utxo **utxos,
	struct bitcoin_tx *tx,
	u8 ****o_sigs);

proxy_stat proxy_handle_sign_remote_commitment_tx(
	struct bitcoin_tx *tx,
	struct pubkey *remote_funding_pubkey,
	struct amount_sat *funding,
	struct node_id *peer_id,
	u64 dbid,
	struct witscript const **output_witscripts,
	struct pubkey *remote_per_commit,
	bool option_static_remotekey,
	u8 ****o_sigs);

#ifdef __cplusplus
} /* extern C */
#endif
