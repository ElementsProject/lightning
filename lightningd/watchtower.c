#include "watchtower.h"

#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
#include <bitcoin/tx.h>
#include <common/htlc_tx.h>
#include <common/key_derive.h>
#include <common/keyset.h>
#include <hsmd/gen_hsm_wire.h>
#include <lightningd/channel.h>
#include <lightningd/peer_control.h>
#include <wire/wire_sync.h>

static const u8 ONE = 0x1;

const struct bitcoin_tx *
penalty_tx_create(const tal_t *ctx, struct lightningd *ld,
		  const struct channel *channel,
		  const struct secret *revocation_preimage,
		  const struct bitcoin_txid *commitment_txid,
		  s16 to_them_outnum, struct amount_sat to_them_sats)
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
	struct pubkey final_key;
	u8 **witness;
	u32 remote_to_self_delay = channel->channel_info.their_config.to_self_delay;
	const struct amount_sat dust_limit = channel->our_config.dust_limit;
	u32 feerate_per_kw = try_get_feerate(ld->topology, FEERATE_PENALTY);
	BUILD_ASSERT(sizeof(struct secret) == sizeof(*revocation_preimage));
	const struct secret remote_per_commitment_secret = *revocation_preimage;
	struct pubkey remote_per_commitment_point;
	struct basepoints basepoints[NUM_SIDES];
	u64 channel_dbid = channel->dbid;
	basepoints[LOCAL] = channel->local_basepoints;
	basepoints[REMOTE] = channel->channel_info.theirbase;

	if (to_them_outnum == -1 ||
	    amount_sat_less_eq(to_them_sats, dust_limit)) {
		log_unusual(channel->log,
			    "Cannot create penalty transaction because there "
			    "is no non-dust to_them output in the commitment.");
		return NULL;
	}

	if (!pubkey_from_secret(&remote_per_commitment_secret, &remote_per_commitment_point))
		fatal("Failed derive from per_commitment_secret %s",
		      type_to_string(tmpctx, struct secret,
				     &remote_per_commitment_secret));

	if (!bip32_pubkey(ld->wallet->bip32_base, &final_key,
			  channel->final_key_idx)) {
		fatal("Could not derive onchain key %" PRIu64,
		      channel->final_key_idx);
	}

	if (!derive_keyset(&remote_per_commitment_point,
			   &basepoints[REMOTE],
			   &basepoints[LOCAL],
			   option_static_remotekey,
			   &keyset))
		abort(); /* TODO(cdecker) Handle a bit more gracefully */
	wscript = bitcoin_wscript_to_local(tmpctx, remote_to_self_delay,
					   &keyset.self_revocation_key,
					   &keyset.self_delayed_payment_key);

	tx = bitcoin_tx(ctx, chainparams, 1, 1, locktime);
	bitcoin_tx_add_input(tx, commitment_txid, to_them_outnum, 0xFFFFFFFF,
			     to_them_sats, NULL);

	bitcoin_tx_add_output(tx, scriptpubkey_p2wpkh(tx, &final_key),
			      to_them_sats);

	/* Worst-case sig is 73 bytes */
	weight = bitcoin_tx_weight(tx) + 1 + 3 + 73 + 0 + tal_count(wscript);
	weight = elements_add_overhead(weight, 1, 1);
	fee = amount_tx_fee(feerate_per_kw, weight);

	if (!amount_sat_add(&min_out, dust_limit, fee))
		log_broken(channel->log,
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
		log_broken(channel->log,
			   "TX can't afford minimal feerate"
			   "; setting output to %s",
			   type_to_string(tmpctx, struct amount_sat, &amt));
	}
	bitcoin_tx_output_set_amount(tx, 0, amt);
	bitcoin_tx_finalize(tx);

	u8 *hsm_sign_msg =
	    towire_hsm_sign_penalty_to_us(ctx, &remote_per_commitment_secret, tx,
					  wscript, *tx->input_amounts[0],
					  &channel->peer->id, &channel_dbid);

	if (!wire_sync_write(ld->hsm_fd, take(hsm_sign_msg)))
		log_broken(channel->log, "Writing sign request to hsm");

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
	if (!msg || !fromwire_hsm_sign_tx_reply(msg, &sig)) {
		fatal("Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));
	}

	witness = bitcoin_witness_sig_and_element(tx, &sig, &ONE, sizeof(ONE),
						  wscript);

	bitcoin_tx_input_set_witness(tx, 0, take(witness));
	return tx;
}
