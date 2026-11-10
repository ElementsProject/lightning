#include "config.h"
#include <bitcoin/locktime.h>
#include <bitcoin/script.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/mem/mem.h>
#include <common/derive_basepoints.h>
#include <common/hsm_secret.h>
#include <common/htlc_tx.h>
#include <common/key_derive.h>
#include <common/keyset.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <tools/hsmtool-recoverhtlc.h>
#include <tools/lightning-hsmtool.h>

static bool derive_channel_basepoints(
	const struct node_id *peer_id,
	u64 channel_dbid,
	const char *hsm_secret_path,
	struct recoverhtlc_keys *keys,
	struct secret *htlc_basepoint_secret)
{
	struct secret hsm_secret, channel_seed;
	struct hsm_secret *hsms
		= hsmtool_load_hsm_secret(tmpctx, hsm_secret_path);

	/* Channel derivation always uses the first 32 bytes. */
	memcpy(hsm_secret.data, hsms->secret_data, sizeof(hsm_secret.data));
	derive_channel_seed(&channel_seed, hsm_secret.data,
			    peer_id, channel_dbid);

	if (!derive_htlc_basepoint(&channel_seed, &keys->our_htlc_basepoint,
				   htlc_basepoint_secret))
		return false;
	return derive_revocation_basepoint(&channel_seed,
					   &keys->our_revocation_basepoint,
					   NULL);
}

/* Derive keys to spend our HTLC outputs on the peer's commitment. */
bool hsmtool_recoverhtlc_derive_keys(
	const struct node_id *peer_id,
	u64 channel_dbid,
	const struct pubkey *commitment_point,
	const struct pubkey *remote_htlc_basepoint,
	const char *hsm_secret_path,
	struct recoverhtlc_keys *keys)
{
	struct secret htlc_basepoint_secret;

	if (!derive_channel_basepoints(peer_id, channel_dbid, hsm_secret_path,
				       keys, &htlc_basepoint_secret))
		return false;

	/* BOLT #3:
	 *
	 * pubkey = basepoint
	 *	    + SHA256(per_commitment_point || basepoint) * G
	 */
	if (!derive_simple_privkey(&htlc_basepoint_secret,
				   &keys->our_htlc_basepoint,
				   commitment_point,
				   &keys->our_htlc_privkey)
	    || !derive_simple_key(&keys->our_htlc_basepoint,
				  commitment_point,
				  &keys->our_htlc_key)
	    || !derive_simple_key(remote_htlc_basepoint,
				  commitment_point,
				  &keys->their_htlc_key))
		return false;

	/* Peer commitment: our basepoint, their commitment point. */
	return derive_revocation_key(&keys->our_revocation_basepoint,
				     commitment_point,
				     &keys->revocation_key);
}

/* Rebuild an HTLC witness script from the peer's commitment. */
static u8 *recovery_wscript(
	const tal_t *ctx,
	enum recoverhtlc_kind kind,
	bool anchors,
	const struct recoverhtlc_keys *keys,
	const struct ripemd160 *payment_ripemd,
	u32 cltv_expiry)
{
	struct abs_locktime expiry;
	struct keyset keyset = {
		.self_revocation_key = keys->revocation_key,
		.self_htlc_key = keys->their_htlc_key,
		.other_htlc_key = keys->our_htlc_key,
	};

	switch (kind) {
	/* The peer offered it, so this is their offered HTLC script. */
	case HTLC_THEY_OFFERED:
		return htlc_offered_wscript(ctx, payment_ripemd, &keyset,
					   anchors, false);

	/* We offered it, so this is the peer's received HTLC script. */
	case HTLC_WE_OFFERED:
		if (!blocks_to_abs_locktime(cltv_expiry, &expiry))
			return NULL;
		return htlc_received_wscript(ctx, payment_ripemd, &expiry,
					    &keyset, anchors, false);
	}
	abort();
}

/* Collect every output with this witness script, including identical MPPs. */
struct recoverhtlc_match *hsmtool_recoverhtlc_match_script(
	const tal_t *ctx,
	const struct bitcoin_tx *tx,
	enum recoverhtlc_kind kind,
	bool anchors,
	const u8 *wscript)
{
	struct recoverhtlc_match *match = tal(ctx, struct recoverhtlc_match);
	/* Commitment outputs contain the P2WSH hash, not the witness script. */
	const u8 *scriptpubkey = scriptpubkey_p2wsh(tmpctx, wscript);

	match->kind = kind;
	match->anchors = anchors;
	match->wscript = tal_dup_arr(match, u8, wscript, tal_bytelen(wscript), 0);
	match->outnums = tal_arr(match, size_t, 0);

	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		const struct wally_tx_output *output = &tx->wtx->outputs[i];

		if (!memeq(output->script, output->script_len,
			   scriptpubkey, tal_bytelen(scriptpubkey)))
			continue;
		tal_arr_expand(&match->outnums, i);
	}

	if (tal_count(match->outnums) == 0)
		return tal_free(match);
	return match;
}

/* Find the requested HTLC without requiring its channel type. */
struct recoverhtlc_match *hsmtool_recoverhtlc_find_outputs(
	const tal_t *ctx,
	const struct bitcoin_tx *tx,
	enum recoverhtlc_kind kind,
	const struct recoverhtlc_keys *keys,
	const struct sha256 *payment_hash,
	u32 cltv_expiry)
{
	struct ripemd160 payment_ripemd;

	ripemd160(&payment_ripemd,
		  payment_hash->u.u8, sizeof(payment_hash->u.u8));

	/* Anchors append `1 CSV DROP`, changing the P2WSH hash.  Try both
	 * forms; only the negotiated form can match a commitment output. */
	for (int anchors = 0; anchors <= 1; anchors++) {
		struct recoverhtlc_match *match;
		const u8 *wscript = recovery_wscript(
			tmpctx, kind, anchors, keys,
			&payment_ripemd, cltv_expiry);

		if (!wscript)
			return NULL;
		match = hsmtool_recoverhtlc_match_script(
			ctx, tx, kind, anchors, wscript);
		/* A match also records which anchor form was used. */
		if (match)
			return match;
	}
	return NULL;
}
