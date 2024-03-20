#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <channeld/channeld.h>
#include <channeld/watchtower.h>
#include <common/features.h>
#include <common/htlc_tx.h>
#include <common/keyset.h>
#include <common/psbt_keypath.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <hsmd/hsmd_wiregen.h>
#include <wire/wire_sync.h>

static const u8 ONE = 0x1;

const struct bitcoin_tx *
penalty_tx_create(const tal_t *ctx,
		  const struct channel *channel,
		  u32 penalty_feerate,
		  u32 *final_index,
		  struct ext_key *final_ext_key,
		  u8 *final_scriptpubkey,
		  const struct secret *revocation_preimage,
		  const struct bitcoin_txid *commitment_txid,
		  s16 to_them_outnum, struct amount_sat to_them_sats,
		  int hsm_fd)
{
	u8 *wscript;
	struct bitcoin_tx *tx;
	struct keyset keyset;
	size_t weight;
	const u8 *msg;
	struct amount_sat fee, min_out, amt;
	struct bitcoin_signature sig;
	u32 locktime = 0;
	bool option_static_remotekey = channel_has(channel, OPT_STATIC_REMOTEKEY);
	u8 **witness;
	u32 remote_to_self_delay = channel->config[REMOTE].to_self_delay;
	const struct amount_sat dust_limit = channel->config[LOCAL].dust_limit;
	BUILD_ASSERT(sizeof(struct secret) == sizeof(*revocation_preimage));
	const struct secret remote_per_commitment_secret = *revocation_preimage;
	struct pubkey remote_per_commitment_point;
	const struct basepoints *basepoints = channel->basepoints;
	struct bitcoin_outpoint outpoint;

	if (to_them_outnum == -1 ||
	    amount_sat_less_eq(to_them_sats, dust_limit)) {
		status_debug(
			    "Cannot create penalty transaction because there "
			    "is no non-dust to_them output in the commitment.");
		return NULL;
	}

	outpoint.txid = *commitment_txid;
	outpoint.n = to_them_outnum;

	if (!pubkey_from_secret(&remote_per_commitment_secret, &remote_per_commitment_point))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed derive from per_commitment_secret %s",
			      fmt_secret(tmpctx, &remote_per_commitment_secret));

	if (!derive_keyset(&remote_per_commitment_point,
			   &basepoints[REMOTE],
			   &basepoints[LOCAL],
			   option_static_remotekey,
			   &keyset))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed deriving keyset");

	/* FIXME: csv_lock */
	wscript = bitcoin_wscript_to_local(tmpctx, remote_to_self_delay, 1,
					   &keyset.self_revocation_key,
					   &keyset.self_delayed_payment_key);

	tx = bitcoin_tx(ctx, chainparams, 1, 1, locktime);
	bitcoin_tx_add_input(tx, &outpoint, 0xFFFFFFFF,
			     NULL, to_them_sats, NULL, wscript);

	bitcoin_tx_add_output(tx, final_scriptpubkey, NULL, to_them_sats);
	assert((final_index == NULL) == (final_ext_key == NULL));
	if (final_index) {
		size_t script_len = tal_bytelen(final_scriptpubkey);
		bool is_tr = is_p2tr(final_scriptpubkey, script_len, NULL);
		psbt_add_keypath_to_last_output(tx, *final_index,
						final_ext_key, is_tr);
        }

	/* Worst-case sig is 73 bytes */
	weight = bitcoin_tx_weight(tx) + 1 + 3 + 73 + 0 + tal_count(wscript);
	weight += elements_tx_overhead(chainparams, 1, 1);
	fee = amount_tx_fee(penalty_feerate, weight);

	if (!amount_sat_add(&min_out, dust_limit, fee))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot add dust_limit %s and fee %s",
			      fmt_amount_sat(tmpctx, dust_limit),
			      fmt_amount_sat(tmpctx, fee));

	if (amount_sat_less(to_them_sats, min_out)) {
		/* FIXME: We should use SIGHASH_NONE so others can take it */
		/* We use the minimum possible fee here; if it doesn't
		 * propagate, who cares? */
		fee = amount_tx_fee(FEERATE_FLOOR, weight);
	}

	/* This can only happen if feerate_floor() is still too high; shouldn't
	 * happen! */
	if (!amount_sat_sub(&amt, to_them_sats, fee)) {
		amt = dust_limit;
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			   "TX can't afford minimal feerate"
			   "; setting output to %s",
			   fmt_amount_sat(tmpctx, amt));
	}
	bitcoin_tx_output_set_amount(tx, 0, amt);
	bitcoin_tx_finalize(tx);

	u8 *hsm_sign_msg =
	    towire_hsmd_sign_penalty_to_us(tmpctx, &remote_per_commitment_secret,
					  tx, wscript);

	msg = hsm_req(tmpctx, hsm_sign_msg);
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	witness = bitcoin_witness_sig_and_element(tx, &sig, &ONE, sizeof(ONE),
						  wscript);

	bitcoin_tx_input_set_witness(tx, 0, take(witness));
	return tx;
}
