#include "watchtower.h"

#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
#include <bitcoin/tx.h>
#include <common/htlc_tx.h>
#include <common/key_derive.h>
#include <common/keyset.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <hsmd/hsmd_wiregen.h>
#include <wire/wire_sync.h>

static const u8 ONE = 0x1;

const struct bitcoin_tx *
penalty_tx_create(const tal_t *ctx,
		  const struct channel *channel,
		  u32 penalty_feerate,
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
	u8 *msg;
	struct amount_sat fee, min_out, amt;
	struct bitcoin_signature sig;
	u32 locktime = 0;
	bool option_static_remotekey = channel->option_static_remotekey;
	u8 **witness;
	u32 remote_to_self_delay = channel->config[REMOTE].to_self_delay;
	const struct amount_sat dust_limit = channel->config[LOCAL].dust_limit;
	BUILD_ASSERT(sizeof(struct secret) == sizeof(*revocation_preimage));
	const struct secret remote_per_commitment_secret = *revocation_preimage;
	struct pubkey remote_per_commitment_point;
	const struct basepoints *basepoints = channel->basepoints;

	if (to_them_outnum == -1 ||
	    amount_sat_less_eq(to_them_sats, dust_limit)) {
		status_debug(
			    "Cannot create penalty transaction because there "
			    "is no non-dust to_them output in the commitment.");
		return NULL;
	}

	if (!pubkey_from_secret(&remote_per_commitment_secret, &remote_per_commitment_point))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed derive from per_commitment_secret %s",
			      type_to_string(tmpctx, struct secret,
					     &remote_per_commitment_secret));

	if (!derive_keyset(&remote_per_commitment_point,
			   &basepoints[REMOTE],
			   &basepoints[LOCAL],
			   option_static_remotekey,
			   &keyset))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed deriving keyset");

	wscript = bitcoin_wscript_to_local(tmpctx, remote_to_self_delay,
					   &keyset.self_revocation_key,
					   &keyset.self_delayed_payment_key);

	tx = bitcoin_tx(ctx, chainparams, 1, 1, locktime);
	bitcoin_tx_add_input(tx, commitment_txid, to_them_outnum, 0xFFFFFFFF,
			     NULL, to_them_sats, NULL, wscript);

	bitcoin_tx_add_output(tx, final_scriptpubkey, NULL, to_them_sats);

	/* Worst-case sig is 73 bytes */
	weight = bitcoin_tx_weight(tx) + 1 + 3 + 73 + 0 + tal_count(wscript);
	weight = elements_add_overhead(weight, 1, 1);
	fee = amount_tx_fee(penalty_feerate, weight);

	if (!amount_sat_add(&min_out, dust_limit, fee))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot add dust_limit %s and fee %s",
			      type_to_string(tmpctx, struct amount_sat, &dust_limit),
			      type_to_string(tmpctx, struct amount_sat, &fee));

	if (amount_sat_less(to_them_sats, min_out)) {
		/* FIXME: We should use SIGHASH_NONE so others can take it */
		fee = amount_tx_fee(feerate_floor(), weight);
	}

	/* This can only happen if feerate_floor() is still too high; shouldn't
	 * happen! */
	if (!amount_sat_sub(&amt, to_them_sats, fee)) {
		amt = dust_limit;
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			   "TX can't afford minimal feerate"
			   "; setting output to %s",
			   type_to_string(tmpctx, struct amount_sat, &amt));
	}
	bitcoin_tx_output_set_amount(tx, 0, amt);
	bitcoin_tx_finalize(tx);

	u8 *hsm_sign_msg =
	    towire_hsmd_sign_penalty_to_us(ctx, &remote_per_commitment_secret,
					  tx, wscript);

	if (!wire_sync_write(hsm_fd, take(hsm_sign_msg)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Writing sign request to hsm");

	msg = wire_sync_read(tmpctx, hsm_fd);
	if (!msg || !fromwire_hsmd_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	witness = bitcoin_witness_sig_and_element(tx, &sig, &ONE, sizeof(ONE),
						  wscript);

	bitcoin_tx_input_set_witness(tx, 0, take(witness));
	return tx;
}
