#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <common/channel_config.h>
#include <common/features.h>
#include <common/initial_commit_tx.h>
#include <common/shutdown_scriptpubkey.h>
#include <common/status.h>
#include <hsmd/hsmd_wiregen.h>
#include <openingd/common.h>
#include <wire/wire_sync.h>

/*~ This is the key function that checks that their configuration is reasonable:
 * it applied for both the case where they're trying to open a channel, and when
 * they've accepted our open. */
bool check_config_bounds(const tal_t *ctx,
			 struct amount_sat funding,
			 u32 feerate_per_kw,
			 u32 max_to_self_delay,
			 struct amount_msat min_effective_htlc_capacity,
			 const struct channel_config *remoteconf,
			 const struct channel_config *localconf,
			 bool option_anchors_zero_fee_htlc_tx,
			 char **err_reason)
{
	struct amount_sat capacity;
	struct amount_sat reserve;
	struct amount_sat fee;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `to_self_delay` is unreasonably large.
	 */
	if (remoteconf->to_self_delay > max_to_self_delay) {
		*err_reason = tal_fmt(ctx,
				      "to_self_delay %u larger than %u",
				      remoteconf->to_self_delay,
				      max_to_self_delay);
		return false;
	}

	/* BOLT #2:
	 *
	 * The receiving node MAY fail the channel if:
	 *...
	 *   - `funding_satoshis` is too small.
	 *   - it considers `htlc_minimum_msat` too large.
	 *   - it considers `max_htlc_value_in_flight_msat` too small.
	 *   - it considers `channel_reserve_satoshis` too large.
	 *   - it considers `max_accepted_htlcs` too small.
	 */
	/* We accumulate this into an effective bandwidth minimum. */

	/* Add both reserves to deduct from capacity. */
	if (!amount_sat_add(&reserve,
			    remoteconf->channel_reserve,
			    localconf->channel_reserve)) {
		*err_reason = tal_fmt(ctx,
				      "channel_reserve_satoshis %s"
				      " too large",
				      fmt_amount_sat(ctx, remoteconf->channel_reserve));
		return false;
	}

	/* BOLT #2:
	 *  - if `option_anchors` applies to this commitment
	 *    transaction and the sending node is the funder:
	 *   - MUST be able to additionally pay for `to_local_anchor` and
	 *    `to_remote_anchor` above its reserve.
	 */
	/* (We simply include in "reserve" here if they opened). */
	if (option_anchors_zero_fee_htlc_tx
	    && !amount_sat_add(&reserve, reserve, AMOUNT_SAT(660))) {
		*err_reason = tal_fmt(ctx,
				      "cannot add anchors to reserve %s",
				      fmt_amount_sat(ctx, reserve));
		return false;
	}

	/* If reserves are larger than total sat, we fail. */
	if (!amount_sat_sub(&capacity, funding, reserve)) {
		*err_reason = tal_fmt(ctx, "channel_reserve_satoshis %s"
				      " and %s too large for funding %s",
				      fmt_amount_sat(ctx, remoteconf->channel_reserve),
				      fmt_amount_sat(ctx, localconf->channel_reserve),
				      fmt_amount_sat(ctx, funding));
		return false;
	}

	/* They have to pay for fees, too.  Assuming HTLC is dust, though,
	 * we don't account for an HTLC output. */
	fee = commit_tx_base_fee(feerate_per_kw, 0,
				 false,
				 option_anchors_zero_fee_htlc_tx);
	if (!amount_sat_sub(&capacity, capacity, fee)) {
		*err_reason = tal_fmt(ctx, "channel_reserve_satoshis %s"
				      " and %s plus fee %s too large for "
				      "funding %s",
				      fmt_amount_sat(tmpctx, remoteconf->channel_reserve),
				      fmt_amount_sat(tmpctx, localconf->channel_reserve),
				      fmt_amount_sat(tmpctx, fee),
				      fmt_amount_sat(tmpctx, funding));
		return false;
	}

	/* If they set the max HTLC value to less than that number, it caps
	 * the channel capacity. */
	if (amount_sat_greater(capacity,
			       amount_msat_to_sat_round_down(remoteconf->max_htlc_value_in_flight)))
		capacity = amount_msat_to_sat_round_down(remoteconf->max_htlc_value_in_flight);

	/* If the minimum htlc is greater than the capacity, the channel is
	 * useless. */
	if (amount_msat_greater_sat(remoteconf->htlc_minimum, capacity)) {
		*err_reason = tal_fmt(ctx, "htlc_minimum_msat %s"
				      " too large for funding %s"
				      " capacity_msat %s",
				      fmt_amount_msat(ctx, remoteconf->htlc_minimum),
				      fmt_amount_sat(ctx, funding),
				      fmt_amount_sat(ctx, capacity));
		return false;
	}

	/* If the resulting channel doesn't meet our minimum "effective capacity"
	 * set by lightningd, don't bother opening it. */
	if (amount_msat_greater_sat(min_effective_htlc_capacity,
				    capacity)) {
		struct amount_sat min_effective_htlc_capacity_sat =
			amount_msat_to_sat_round_down(min_effective_htlc_capacity);

		*err_reason = tal_fmt(ctx,
				      "channel capacity with funding %s,"
				      " reserves %s/%s,"
				      " max_htlc_value_in_flight_msat is %s,"
				      " channel capacity is %s, which is below %s",
				      fmt_amount_sat(ctx, funding),
				      fmt_amount_sat(ctx, remoteconf->channel_reserve),
				      fmt_amount_sat(ctx, localconf->channel_reserve),
				      fmt_amount_msat(ctx, remoteconf->max_htlc_value_in_flight),
				      fmt_amount_sat(ctx, capacity),
				      fmt_amount_sat(ctx, min_effective_htlc_capacity_sat));
		return false;
	}

	/* We don't worry about how many HTLCs they accept, as long as > 0! */
	if (remoteconf->max_accepted_htlcs == 0) {
		*err_reason = tal_fmt(ctx,
				      "max_accepted_htlcs %u invalid",
				      remoteconf->max_accepted_htlcs);
		return false;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `max_accepted_htlcs` is greater than 483.
	 */
	if (remoteconf->max_accepted_htlcs > 483) {
		*err_reason = tal_fmt(ctx,
				      "max_accepted_htlcs %u too large",
				      remoteconf->max_accepted_htlcs);
		return false;
	}

	return true;
}

u8 *no_upfront_shutdown_script(const tal_t *ctx,
			       bool developer,
			       struct feature_set *our_features,
			       const u8 *their_features)
{
	if (developer) {
		/* This is a hack, for feature testing */
		const char *e = getenv("DEV_OPENINGD_UPFRONT_SHUTDOWN_SCRIPT");
		if (e)
			return tal_hexdata(ctx, e, strlen(e));
	}

	/* BOLT #2:
	 *
	 * - if both nodes advertised the `option_upfront_shutdown_script`
	 *   feature:
	 *   - MUST include `upfront_shutdown_script` with either a valid
	 *     `shutdown_scriptpubkey` as required by `shutdown`
	 *     `scriptpubkey`, or a zero-length `shutdown_scriptpubkey`
	 *     (ie. `0x0000`).
	 */
	if (feature_negotiated(our_features, their_features,
			       OPT_UPFRONT_SHUTDOWN_SCRIPT))
		return tal_arr(ctx, u8, 0);

	return NULL;
}

bool anchors_negotiated(struct feature_set *our_features,
			const u8 *their_features)
{
	return feature_negotiated(our_features, their_features,
				  OPT_ANCHOR_OUTPUTS_DEPRECATED)
		|| feature_negotiated(our_features,
				      their_features,
				      OPT_ANCHORS_ZERO_FEE_HTLC_TX);
}

char *validate_remote_upfront_shutdown(const tal_t *ctx,
				       struct feature_set *our_features,
				       const u8 *their_features,
				       u8 *shutdown_scriptpubkey STEALS,
				       u8 **state_script)
{
	bool anysegwit = feature_negotiated(our_features,
					    their_features,
					    OPT_SHUTDOWN_ANYSEGWIT);

	bool anchors = anchors_negotiated(our_features, their_features);
	/* BOLT #2:
	 *
	 * - MUST include `upfront_shutdown_script` with either a valid
         *   `shutdown_scriptpubkey` as required by `shutdown` `scriptpubkey`,
         *   or a zero-length `shutdown_scriptpubkey` (ie. `0x0000`).
	 */
	/* We turn empty into NULL. */
	if (tal_bytelen(shutdown_scriptpubkey) == 0)
		shutdown_scriptpubkey = tal_free(shutdown_scriptpubkey);

	*state_script = tal_steal(ctx, shutdown_scriptpubkey);

	if (shutdown_scriptpubkey
	    && !valid_shutdown_scriptpubkey(shutdown_scriptpubkey, anysegwit, !anchors))
		return tal_fmt(tmpctx,
			       "Unacceptable upfront_shutdown_script %s",
			       tal_hex(tmpctx, shutdown_scriptpubkey));
	return NULL;
}


void validate_initial_commitment_signature(int hsm_fd,
					   struct bitcoin_tx *tx,
					   struct bitcoin_signature *sig)
{
	struct existing_htlc **htlcs;
	struct bitcoin_signature *htlc_sigs;
	u32 feerate;
	u64 commit_num;
	const u8 *msg;
	struct secret *old_secret;
	struct pubkey next_point;

	/* Validate the counterparty's signature. */
	htlcs = tal_arr(NULL, struct existing_htlc *, 0);
	htlc_sigs = tal_arr(NULL, struct bitcoin_signature, 0);
	feerate = 0; /* unused since there are no htlcs */
	commit_num = 0;
	msg = towire_hsmd_validate_commitment_tx(NULL,
						 tx,
						 (const struct simple_htlc **) htlcs,
						 commit_num,
						 feerate,
						 sig,
						 htlc_sigs);
	tal_free(htlc_sigs);
	tal_free(htlcs);
	wire_sync_write(hsm_fd, take(msg));
	msg = wire_sync_read(tmpctx, hsm_fd);
	if (!fromwire_hsmd_validate_commitment_tx_reply(tmpctx, msg, &old_secret, &next_point))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading validate_commitment_tx reply: %s",
			      tal_hex(tmpctx, msg));
}

