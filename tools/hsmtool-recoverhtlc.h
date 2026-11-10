#ifndef LIGHTNING_TOOLS_HSMTOOL_RECOVERHTLC_H
#define LIGHTNING_TOOLS_HSMTOOL_RECOVERHTLC_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/short_types/short_types.h>

struct node_id;

/* Key names are from the commitment owner's perspective. */
struct recoverhtlc_keys {
	struct pubkey our_htlc_basepoint;
	struct pubkey our_revocation_basepoint;
	struct privkey our_htlc_privkey;
	struct pubkey our_htlc_key;	/* remote_htlcpubkey */
	struct pubkey their_htlc_key;	/* local_htlcpubkey */
	struct pubkey revocation_key;
};

bool hsmtool_recoverhtlc_derive_keys(
	const struct node_id *peer_id,
	u64 channel_dbid,
	const struct pubkey *commitment_point,
	const struct pubkey *remote_htlc_basepoint,
	const char *hsm_secret_path,
	struct recoverhtlc_keys *keys);

#endif /* LIGHTNING_TOOLS_HSMTOOL_RECOVERHTLC_H */
