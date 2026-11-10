#ifndef LIGHTNING_TOOLS_HSMTOOL_RECOVERHTLC_H
#define LIGHTNING_TOOLS_HSMTOOL_RECOVERHTLC_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <bitcoin/tx.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>

struct node_id;

enum recoverhtlc_kind {
	HTLC_THEY_OFFERED,
	HTLC_WE_OFFERED,
};

struct recoverhtlc_match {
	enum recoverhtlc_kind kind;
	bool anchors;
	u8 *wscript;
	size_t *outnums;
};

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

struct recoverhtlc_match *hsmtool_recoverhtlc_match_script(
	const tal_t *ctx,
	const struct bitcoin_tx *tx,
	enum recoverhtlc_kind kind,
	bool anchors,
	const u8 *wscript);

struct recoverhtlc_match *hsmtool_recoverhtlc_find_outputs(
	const tal_t *ctx,
	const struct bitcoin_tx *tx,
	enum recoverhtlc_kind kind,
	const struct recoverhtlc_keys *keys,
	const struct sha256 *payment_hash,
	u32 cltv_expiry);

struct bitcoin_tx *hsmtool_recoverhtlc_sign(
	const tal_t *ctx,
	const struct bitcoin_tx *commitment_tx,
	const struct recoverhtlc_match *match,
	const struct recoverhtlc_keys *keys,
	const u8 *destination_script,
	struct amount_sat output_amount,
	u32 cltv_expiry,
	const struct preimage *preimage);

#endif /* LIGHTNING_TOOLS_HSMTOOL_RECOVERHTLC_H */
