#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <channeld/commit_tx.h>
#include <channeld/full_channel.h>
#include <common/blockheight_states.h>
#include <common/features.h>
#include <common/fee_states.h>
#include <common/htlc_trim.h>
#include <common/htlc_tx.h>
#include <common/htlc_wire.h>
#include <common/keyset.h>
#include <common/memleak.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <stdio.h>
  /* Needs to be at end, since it doesn't include its own hdrs */
  #include "full_channel_error_names_gen.h"

static void memleak_help_htlcmap(struct htable *memtable,
				 struct htlc_map *htlcs)
{
	memleak_scan_htable(memtable, &htlcs->raw);
}

/* This is a dangerous thing!  Because we apply HTLCs in many places
 * in bulk, we can temporarily go negative.  You must check balance_ok()
 * at the end! */
struct balance {
	s64 msat;
};

static void to_balance(struct balance *balance,
		       const struct amount_msat msat)
{
	balance->msat = msat.millisatoshis; /* Raw: balance */
	assert(balance->msat >= 0);
}

/* What does adding the HTLC do to the balance for this side (subtracts) */
static void balance_add_htlc(struct balance *balance,
			     const struct htlc *htlc,
			     enum side side)
{
	if (htlc_owner(htlc) == side)
		balance->msat -= htlc->amount.millisatoshis; /* Raw: balance */
}

/* What does removing the HTLC do to the balance for this side (adds) */
static void balance_remove_htlc(struct balance *balance,
				const struct htlc *htlc,
				enum side side)
{
	enum side paid_to;

	/* Fulfilled HTLCs are paid to recipient, otherwise returns to owner */
	if (htlc->r)
		paid_to = !htlc_owner(htlc);
	else
		paid_to = htlc_owner(htlc);

	if (side == paid_to)
		balance->msat += htlc->amount.millisatoshis; /* Raw: balance */
}

static bool balance_ok(const struct balance *balance,
		       struct amount_msat *msat)
	WARN_UNUSED_RESULT;

static bool balance_ok(const struct balance *balance,
		       struct amount_msat *msat)
{
	if (balance->msat < 0)
		return false;
	*msat = amount_msat(balance->msat);
	return true;
}

struct channel *new_full_channel(const tal_t *ctx,
				 const struct channel_id *cid,
				 const struct bitcoin_outpoint *funding,
				 u32 minimum_depth,
				 const struct height_states *blockheight_states,
				 u32 lease_expiry,
				 struct amount_sat funding_sats,
				 struct amount_msat local_msat,
				 const struct fee_states *fee_states TAKES,
				 const struct channel_config *local,
				 const struct channel_config *remote,
				 const struct basepoints *local_basepoints,
				 const struct basepoints *remote_basepoints,
				 const struct pubkey *local_funding_pubkey,
				 const struct pubkey *remote_funding_pubkey,
				 const struct channel_type *type TAKES,
				 bool option_wumbo,
				 enum side opener)
{
	struct channel *channel = new_initial_channel(ctx,
						      cid,
						      funding,
						      minimum_depth,
						      blockheight_states,
						      lease_expiry,
						      funding_sats,
						      local_msat,
						      fee_states,
						      local, remote,
						      local_basepoints,
						      remote_basepoints,
						      local_funding_pubkey,
						      remote_funding_pubkey,
						      type,
						      option_wumbo,
						      opener);

	if (channel) {
		channel->htlcs = tal(channel, struct htlc_map);
		htlc_map_init(channel->htlcs);
		memleak_add_helper(channel->htlcs, memleak_help_htlcmap);
	}
	return channel;
}

static void htlc_arr_append(const struct htlc ***arr, const struct htlc *htlc)
{
	if (!arr)
		return;
	tal_arr_expand(arr, htlc);
}

static void dump_htlc(const struct htlc *htlc, const char *prefix)
{
	enum htlc_state remote_state;

	if (htlc->state <= RCVD_REMOVE_ACK_REVOCATION)
		remote_state = htlc->state + 10;
	else
		remote_state = htlc->state - 10;

	status_debug("%s: HTLC %s %"PRIu64" = %s/%s %s",
		     prefix,
		     htlc_owner(htlc) == LOCAL ? "LOCAL" : "REMOTE",
		     htlc->id,
		     htlc_state_name(htlc->state),
		     htlc_state_name(remote_state),
		     htlc->r ? "FULFILLED" : htlc->failed ? "FAILED"
		     : "");
}

void dump_htlcs(const struct channel *channel, const char *prefix)
{
#ifdef SUPERVERBOSE
	struct htlc_map_iter it;
	const struct htlc *htlc;

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		dump_htlc(htlc, prefix);
	}
#endif
}

/* Returns up to three arrays:
 * committed: HTLCs currently committed.
 * pending_removal: HTLCs pending removal (subset of committed)
 * pending_addition: HTLCs pending addition (no overlap with committed)
 *
 * Also returns number of HTLCs for other side.
 */
static size_t gather_htlcs(const tal_t *ctx,
			   const struct channel *channel,
			   enum side side,
			   const struct htlc ***committed,
			   const struct htlc ***pending_removal,
			   const struct htlc ***pending_addition)
{
	struct htlc_map_iter it;
	const struct htlc *htlc;
	const int committed_flag = HTLC_FLAG(side, HTLC_F_COMMITTED);
	const int pending_flag = HTLC_FLAG(side, HTLC_F_PENDING);
	size_t num_other_side = 0;

	*committed = tal_arr(ctx, const struct htlc *, 0);
	if (pending_removal)
		*pending_removal = tal_arr(ctx, const struct htlc *, 0);
	if (pending_addition)
		*pending_addition = tal_arr(ctx, const struct htlc *, 0);

	if (!channel->htlcs)
		return num_other_side;

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		if (htlc_has(htlc, committed_flag)) {
#ifdef SUPERVERBOSE
			dump_htlc(htlc, "COMMITTED");
#endif
			htlc_arr_append(committed, htlc);
			if (htlc_has(htlc, pending_flag)) {
#ifdef SUPERVERBOSE
				dump_htlc(htlc, "REMOVING");
#endif
				htlc_arr_append(pending_removal, htlc);
			} else if (htlc_owner(htlc) != side)
				num_other_side++;
		} else if (htlc_has(htlc, pending_flag)) {
			htlc_arr_append(pending_addition, htlc);
#ifdef SUPERVERBOSE
			dump_htlc(htlc, "ADDING");
#endif
			if (htlc_owner(htlc) != side)
				num_other_side++;
		}
	}
	return num_other_side;
}

static bool sum_offered_msatoshis(struct amount_msat *total,
				  const struct htlc **htlcs,
				  enum side side)
{
	size_t i;

	*total = AMOUNT_MSAT(0);
	for (i = 0; i < tal_count(htlcs); i++) {
		if (htlc_owner(htlcs[i]) == side) {
			if (!amount_msat_add(total, *total, htlcs[i]->amount))
				return false;
		}
	}
	return true;
}

static void add_htlcs(struct bitcoin_tx ***txs,
		      const struct htlc **htlcmap,
		      const struct channel *channel,
		      const struct keyset *keyset,
		      enum side side)
{
	struct bitcoin_outpoint outpoint;
	u32 htlc_feerate_per_kw;
	bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	if (channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX))
		htlc_feerate_per_kw = 0;
	else
		htlc_feerate_per_kw = channel_feerate(channel, side);

	/* Get txid of commitment transaction */
	bitcoin_txid((*txs)[0], &outpoint.txid);

	for (outpoint.n = 0; outpoint.n < tal_count(htlcmap); outpoint.n++) {
		const struct htlc *htlc = htlcmap[outpoint.n];
		struct bitcoin_tx *tx;
		struct ripemd160 ripemd;
		const u8 *wscript;

		if (!htlc)
			continue;

		if (htlc_owner(htlc) == side) {
			ripemd160(&ripemd, htlc->rhash.u.u8, sizeof(htlc->rhash.u.u8));
			wscript = htlc_offered_wscript(tmpctx, &ripemd, keyset,
						       option_anchor_outputs,
						       option_anchors_zero_fee_htlc_tx);
			tx = htlc_timeout_tx(*txs, chainparams, &outpoint,
					     wscript,
					     htlc->amount,
					     htlc->expiry.locktime,
					     channel->config[!side].to_self_delay,
					     htlc_feerate_per_kw,
					     keyset,
					     option_anchor_outputs,
					     option_anchors_zero_fee_htlc_tx);
		} else {
			ripemd160(&ripemd, htlc->rhash.u.u8, sizeof(htlc->rhash.u.u8));
			wscript = htlc_received_wscript(tmpctx, &ripemd,
							&htlc->expiry, keyset,
							option_anchor_outputs,
							option_anchors_zero_fee_htlc_tx);
			tx = htlc_success_tx(*txs, chainparams, &outpoint,
					     wscript,
					     htlc->amount,
					     channel->config[!side].to_self_delay,
					     htlc_feerate_per_kw,
					     keyset,
					     option_anchor_outputs,
					     option_anchors_zero_fee_htlc_tx);
		}

		/* Append to array. */
		tal_arr_expand(txs, tx);
	}
}

/* FIXME: We could cache these. */
struct bitcoin_tx **channel_txs(const tal_t *ctx,
				const struct htlc ***htlcmap,
				struct wally_tx_output *direct_outputs[NUM_SIDES],
				const u8 **funding_wscript,
				const struct channel *channel,
				const struct pubkey *per_commitment_point,
				u64 commitment_number,
				enum side side)
{
	return channel_splice_txs(ctx, &channel->funding, channel->funding_sats,
				  htlcmap, direct_outputs, funding_wscript,
				  channel, per_commitment_point,
				  commitment_number, side, 0, 0);
}

struct bitcoin_tx **channel_splice_txs(const tal_t *ctx,
				       const struct bitcoin_outpoint *funding,
				       struct amount_sat funding_sats,
				       const struct htlc ***htlcmap,
				       struct wally_tx_output *direct_outputs[NUM_SIDES],
				       const u8 **funding_wscript,
				       const struct channel *channel,
				       const struct pubkey *per_commitment_point,
				       u64 commitment_number,
				       enum side side,
				       s64 splice_amnt,
				       s64 remote_splice_amnt)
{
	struct bitcoin_tx **txs;
	const struct htlc **committed;
	struct keyset keyset;
	struct amount_msat side_pay, other_side_pay;

	if (!derive_keyset(per_commitment_point,
			   &channel->basepoints[side],
			   &channel->basepoints[!side],
			   channel_has(channel, OPT_STATIC_REMOTEKEY),
			   &keyset))
		return NULL;

	/* Figure out what @side will already be committed to. */
	gather_htlcs(ctx, channel, side, &committed, NULL, NULL);

	/* Generating and saving witness script required to spend
	 * the funding output */
	*funding_wscript = bitcoin_redeem_2of2(ctx,
					      &channel->funding_pubkey[side],
					      &channel->funding_pubkey[!side]);

	side_pay = channel->view[side].owed[side];
	other_side_pay = channel->view[side].owed[!side];

	if (side == LOCAL) {
		if (!amount_msat_add_sat_s64(&side_pay, side_pay, splice_amnt))
			return NULL;
		if (!amount_msat_add_sat_s64(&other_side_pay, other_side_pay, remote_splice_amnt))
			return NULL;
	} else if (side == REMOTE) {
		if (!amount_msat_add_sat_s64(&side_pay, side_pay, remote_splice_amnt))
			return NULL;
		if (!amount_msat_add_sat_s64(&other_side_pay, other_side_pay, splice_amnt))
			return NULL;
	}

	txs = tal_arr(ctx, struct bitcoin_tx *, 1);
	txs[0] = commit_tx(
	    txs, funding,
	    funding_sats,
	    &channel->funding_pubkey[side],
	    &channel->funding_pubkey[!side],
	    channel->opener,
	    channel->config[!side].to_self_delay,
	    channel->lease_expiry,
	    channel_blockheight(channel, side),
	    &keyset, channel_feerate(channel, side),
	    channel->config[side].dust_limit, side_pay,
	    other_side_pay, committed, htlcmap, direct_outputs,
	    commitment_number ^ channel->commitment_number_obscurer,
	    channel_has(channel, OPT_ANCHOR_OUTPUTS),
	    channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX),
	    side);

	/* Set the remote/local pubkeys on the commitment tx psbt */
	psbt_input_add_pubkey(txs[0]->psbt, 0,
			      &channel->funding_pubkey[side], false /* is_taproot */);
	psbt_input_add_pubkey(txs[0]->psbt, 0,
			      &channel->funding_pubkey[!side], false /* is_taproot */);

	add_htlcs(&txs, *htlcmap, channel, &keyset, side);

	tal_free(committed);
	return txs;
}

/* If @side is faced with these HTLCs, how much will it have left
 * above reserve (eg. to pay fees).  Returns false if would be < 0. */
static bool get_room_above_reserve(const struct channel *channel,
				   const struct channel_view *view,
				   const struct htlc **adding,
				   const struct htlc **removing,
				   enum side side,
				   struct amount_msat *remainder)
{
	/* Reserve is set by the *other* side */
	struct amount_sat reserve = channel->config[!side].channel_reserve;
	struct balance balance;
	struct amount_msat owed = view->owed[side];

	/* `lowest_splice_amnt` will always be negative or 0 */
	if (amount_msat_less_eq_sat(owed, amount_sat(-view->lowest_splice_amnt[side]))) {
		status_debug("Relative splice balance invalid");
		return false;
	}

	/* `lowest_splice_amnt` is a relative amount */
	if (!amount_msat_sub_sat(&owed, owed,
				 amount_sat(-view->lowest_splice_amnt[side]))) {
		status_debug("Owed amount should not wrap around from splice");
		return false;
	}

	to_balance(&balance, owed);

	for (size_t i = 0; i < tal_count(removing); i++)
		balance_remove_htlc(&balance, removing[i], side);

	for (size_t i = 0; i < tal_count(adding); i++)
		balance_add_htlc(&balance, adding[i], side);

	/* Can happen if amount completely exceeds capacity */
	if (!balance_ok(&balance, remainder)) {
		status_debug("Failed to add %zu remove %zu htlcs",
			     tal_count(adding), tal_count(removing));
		return false;
	}

	if (!amount_msat_sub_sat(remainder, *remainder, reserve)) {
		status_debug("%s cannot afford htlc: would make balance %s"
			     " below reserve %s",
			     side_to_str(side),
			     type_to_string(tmpctx, struct amount_msat,
					    remainder),
			     type_to_string(tmpctx, struct amount_sat,
					    &reserve));
		return false;
	}
	return true;
}

static size_t num_untrimmed_htlcs(enum side side,
				  struct amount_sat dust_limit,
				  u32 feerate,
				  bool option_anchor_outputs,
				  bool option_anchors_zero_fee_htlc_tx,
				  const struct htlc **committed,
				  const struct htlc **adding,
				  const struct htlc **removing)
{
	return commit_tx_num_untrimmed(committed, feerate, dust_limit,
				       option_anchor_outputs,
				       option_anchors_zero_fee_htlc_tx,
				       side)
		+ commit_tx_num_untrimmed(adding, feerate, dust_limit,
					  option_anchor_outputs,
					  option_anchors_zero_fee_htlc_tx,
					  side)
		- commit_tx_num_untrimmed(removing, feerate, dust_limit,
					  option_anchor_outputs,
					  option_anchors_zero_fee_htlc_tx,
					  side);
}

static struct amount_sat fee_for_htlcs(const struct channel *channel,
				       const struct htlc **committed,
				       const struct htlc **adding,
				       const struct htlc **removing,
				       enum side side)
{
	u32 feerate = channel_feerate(channel, side);
	struct amount_sat dust_limit = channel->config[side].dust_limit;
	size_t untrimmed;
	bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	untrimmed = num_untrimmed_htlcs(side, dust_limit, feerate,
					option_anchor_outputs,
					option_anchors_zero_fee_htlc_tx,
					committed, adding, removing);

	return commit_tx_base_fee(feerate, untrimmed,
				  option_anchor_outputs,
				  option_anchors_zero_fee_htlc_tx);
}

static bool htlc_dust(const struct channel *channel,
		      const struct htlc **committed,
		      const struct htlc **adding,
		      const struct htlc **removing,
		      enum side side,
		      u32 feerate,
		      struct amount_msat *trim_total)
{
	struct amount_sat dust_limit = channel->config[side].dust_limit;
	bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);
	struct amount_msat trim_rmvd = AMOUNT_MSAT(0);

	if (!commit_tx_amount_trimmed(committed, feerate,
				      dust_limit,
				      option_anchor_outputs,
				      option_anchors_zero_fee_htlc_tx,
				      side, trim_total))
		return false;
	if (!commit_tx_amount_trimmed(adding, feerate,
				      dust_limit,
				      option_anchor_outputs,
				      option_anchors_zero_fee_htlc_tx,
				      side, trim_total))
		return false;
	if (!commit_tx_amount_trimmed(removing, feerate,
				      dust_limit,
				      option_anchor_outputs,
				      option_anchors_zero_fee_htlc_tx,
				      side, &trim_rmvd))
		return false;

	return amount_msat_sub(trim_total, *trim_total, trim_rmvd);
}

/*
 * There is a corner case where the opener can spend so much that the
 * non-opener can't add any non-dust HTLCs (since the opener would
 * have to pay the additional fee, but it can't afford to).  This
 * leads to the channel starving at the feast!  This was reported by
 * ACINQ's @t-bast
 * (https://github.com/lightningnetwork/lightning-rfc/issues/728) and
 * demonstrated with Core Lightning by @m-schmoock
 * (https://github.com/ElementsProject/lightning/pull/3498).
 *
 * To mostly avoid this situation, at least from our side, we apply an
 * additional constraint when we're opener trying to add an HTLC: make
 * sure we can afford one more HTLC, even if fees increase by 100%.
 *
 * We could do this for the peer, as well, by rejecting their HTLC
 * immediately in this case.  But rejecting a remote HTLC here causes
 * us to get upset with them and close the channel: we're not well
 * architected to reject HTLCs in channeld (it's usually lightningd's
 * job, but it doesn't have all the channel balance change calculation
 * logic.  So we look after ourselves for now, and hope other nodes start
 * self-regulating too.
 *
 * This mitigation will become BOLT #2 standard by:
 * https://github.com/lightningnetwork/lightning-rfc/issues/740
 */
static bool local_opener_has_fee_headroom(const struct channel *channel,
					  struct amount_msat remainder,
					  const struct htlc **committed,
					  const struct htlc **adding,
					  const struct htlc **removing)
{
	u32 feerate = channel_feerate(channel, LOCAL);
	size_t untrimmed;
	struct amount_sat fee;
	bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	assert(channel->opener == LOCAL);

	/* How many untrimmed at current feerate?   Increasing feerate can
	 * only *reduce* this number, so use current feerate here! */
	untrimmed = num_untrimmed_htlcs(LOCAL, channel->config[LOCAL].dust_limit,
					feerate,
					option_anchor_outputs,
					option_anchors_zero_fee_htlc_tx,
					committed, adding, removing);

	/* Now, how much would it cost us if feerate increases 100% and we added
	 * another HTLC? */
	fee = commit_tx_base_fee(2 * feerate, untrimmed + 1,
				 option_anchor_outputs,
				 option_anchors_zero_fee_htlc_tx);
	if (amount_msat_greater_eq_sat(remainder, fee))
		return true;

	status_debug("Adding HTLC would leave us only %s: we need %s for"
		     " another HTLC if fees increase by 100%% to %uperkw",
		     type_to_string(tmpctx, struct amount_msat, &remainder),
		     type_to_string(tmpctx, struct amount_sat, &fee),
		     feerate + feerate);
	return false;
}

static enum channel_add_err add_htlc(struct channel *channel,
				     enum htlc_state state,
				     u64 id,
				     struct amount_msat amount,
				     u32 cltv_expiry,
				     const struct sha256 *payment_hash,
				     const u8 routing[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)],
				     const struct pubkey *blinding TAKES,
				     struct htlc **htlcp,
				     bool enforce_aggregate_limits,
				     struct amount_sat *htlc_fee,
				     bool err_immediate_failures)
{
	struct htlc *htlc, *old;
	struct amount_msat msat_in_htlcs, committed_msat,
			   adding_msat, removing_msat, htlc_dust_amt;
	enum side sender = htlc_state_owner(state), recipient = !sender;
	const struct htlc **committed, **adding, **removing;
	const struct channel_view *view;
	size_t htlc_count;
	bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);
	u32 feerate, feerate_ceil;

	htlc = tal(tmpctx, struct htlc);

	htlc->id = id;
	htlc->amount = amount;
	htlc->state = state;
	htlc->fail_immediate = false;

	htlc->rhash = *payment_hash;
	htlc->blinding = tal_dup_or_null(htlc, struct pubkey, blinding);
	htlc->failed = NULL;
	htlc->r = NULL;
	htlc->routing = tal_dup_arr(htlc, u8, routing, TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE), 0);

	/* FIXME: Change expiry to simple u32 */

	/* BOLT #2:
	 *
	 * A receiving node:
	 *...
	 *  - if sending node sets `cltv_expiry` to greater or equal to
	 *    500000000:
	 *    - SHOULD send a `warning` and close the connection, or send an
	 *      `error` and fail the channel.
	 */
	if (!blocks_to_abs_locktime(cltv_expiry, &htlc->expiry)) {
		return CHANNEL_ERR_INVALID_EXPIRY;
	}

	old = htlc_get(channel->htlcs, htlc->id, htlc_owner(htlc));
	if (old) {
		if (old->state != htlc->state
		    || !amount_msat_eq(old->amount, htlc->amount)
		    || old->expiry.locktime != htlc->expiry.locktime
		    || !sha256_eq(&old->rhash, &htlc->rhash))
			return CHANNEL_ERR_DUPLICATE_ID_DIFFERENT;
		else
			return CHANNEL_ERR_DUPLICATE;
	}

	/* We're always considering the recipient's view of the channel here */
	view = &channel->view[recipient];

	/* BOLT #2:
	 *
	 * A receiving node:
	 *  - receiving an `amount_msat` equal to 0, OR less than its own
	 *    `htlc_minimum_msat`:
	 *        - SHOULD send a `warning` and close the connection, or send an
	 *        `error` and fail the channel.
	 */
	if (amount_msat_eq(htlc->amount, AMOUNT_MSAT(0))) {
		return CHANNEL_ERR_HTLC_BELOW_MINIMUM;
	}
	if (amount_msat_less(htlc->amount, channel->config[recipient].htlc_minimum)) {
		return CHANNEL_ERR_HTLC_BELOW_MINIMUM;
	}

	/* FIXME: There used to be a requirement that we not send more than
	 * 2^32 msat, *but* only electrum enforced it.  Remove in next version:
	 *
	 * A sending node:
	 *...
	 * - for channels with `chain_hash` identifying the Bitcoin blockchain:
	 *    - MUST set the four most significant bytes of `amount_msat` to 0.
	 */
	if (sender == LOCAL
	    && amount_msat_greater(htlc->amount, chainparams->max_payment)
	    && !channel->option_wumbo) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

	/* Figure out what receiver will already be committed to. */
	htlc_count = gather_htlcs(tmpctx, channel, recipient, &committed, &removing, &adding);
	htlc_arr_append(&adding, htlc);

	/* BOLT #2:
	 *
	 *   - if a sending node adds more than receiver `max_accepted_htlcs`
	 *     HTLCs to its local commitment transaction...
	 *         - SHOULD send a `warning` and close the connection, or send an
	 *         `error` and fail the channel.
	 */
	if (htlc_count + 1 > channel->config[recipient].max_accepted_htlcs) {
		return CHANNEL_ERR_TOO_MANY_HTLCS;
	}

	/* Also *we* should not add more htlc's we configured.  This
	 * mitigates attacks in which a peer can force the opener of
	 * the channel to pay unnecessary onchain fees during a fee
	 * spike with large commitment transactions.
	 */
	if (enforce_aggregate_limits && sender == LOCAL
	    && htlc_count + 1 > channel->config[LOCAL].max_accepted_htlcs) {
		return CHANNEL_ERR_TOO_MANY_HTLCS;
	}

	/* These cannot overflow with HTLC amount limitations, but
	 * maybe adding could later if they try to add a maximal HTLC. */
	if (!sum_offered_msatoshis(&committed_msat,
				   committed, htlc_owner(htlc))
	    || !sum_offered_msatoshis(&removing_msat,
				      removing, htlc_owner(htlc))
	    || !sum_offered_msatoshis(&adding_msat,
				      adding, htlc_owner(htlc))) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

	if (!amount_msat_add(&msat_in_htlcs, committed_msat, adding_msat)
	    || !amount_msat_sub(&msat_in_htlcs, msat_in_htlcs, removing_msat)) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

	/* BOLT #2:
	 *
	 *   - if a sending node... adds more than receiver
	 *     `max_htlc_value_in_flight_msat` worth of offered HTLCs to its
	 *     local commitment transaction:
	 *     - SHOULD send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */

	/* We don't enforce this for channel_force_htlcs: some might already
	 * be fulfilled/failed */
	if (enforce_aggregate_limits
	    && amount_msat_greater(msat_in_htlcs,
				   channel->config[recipient].max_htlc_value_in_flight)) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

	/* BOLT #2:
	 *
	 * A receiving node:
	 *...
	 *  - receiving an `amount_msat` that the sending node cannot afford at
	 *    the current `feerate_per_kw` (while maintaining its channel
	 *    reserve and any `to_local_anchor` and `to_remote_anchor` costs):
	 *      - SHOULD send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (enforce_aggregate_limits) {
		struct amount_msat remainder;
		struct amount_sat fee = fee_for_htlcs(channel,
						      committed,
						      adding,
						      removing,
						      recipient);
		/* set fee output pointer if given */
		if (htlc_fee)
			*htlc_fee = fee;

		/* This is a little subtle:
		 *
		 * The change is being applied to the receiver but it will
		 * come back to the sender after revoke_and_ack.  So the check
		 * here is that the remainder to the sender doesn't go below the
		 * sender's reserve. */
		if (!get_room_above_reserve(channel, view,
					    adding, removing, sender,
					    &remainder))
			return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;

		/* BOLT #3:
		 * If `option_anchors` applies to the commitment
		 * transaction, also subtract two times the fixed anchor size
		 * of 330 sats from the funder (either `to_local` or
		 * `to_remote`).
		 */
		if ((option_anchor_outputs || option_anchors_zero_fee_htlc_tx)
		    && channel->opener == sender
		    && !amount_msat_sub_sat(&remainder, remainder, AMOUNT_SAT(660)))
			return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;

		if (channel->opener== sender) {
			if (amount_msat_less_sat(remainder, fee)) {
				status_debug("Cannot afford fee %s with %s above reserve",
					     type_to_string(tmpctx, struct amount_sat,
							    &fee),
					     type_to_string(tmpctx, struct amount_msat,
							    &remainder));
				return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;
			}

			if (sender == LOCAL
			    && !local_opener_has_fee_headroom(channel,
							      remainder,
							      committed,
							      adding,
							      removing)) {
				return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;
			}
		}

		/* Try not to add a payment which will take opener into fees
		 * on either our side or theirs. */
		if (sender == LOCAL) {
			if (!get_room_above_reserve(channel, view,
						    adding, removing,
						    channel->opener,
						    &remainder))
				return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;

			if ((option_anchor_outputs || option_anchors_zero_fee_htlc_tx)
			    && channel->opener != sender
			    && !amount_msat_sub_sat(&remainder, remainder, AMOUNT_SAT(660)))
				return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;

			/* Should be able to afford both their own commit tx
			 * fee, and other's commit tx fee, which are subtly
			 * different! */
			fee = fee_for_htlcs(channel,
					    committed,
					    adding,
					    removing,
					    channel->opener);
			/* set fee output pointer if given */
			if (htlc_fee && amount_sat_greater(fee, *htlc_fee))
				*htlc_fee = fee;
			if (amount_msat_less_sat(remainder, fee)) {
				status_debug("Funder could not afford own fee %s with %s above reserve",
					     type_to_string(tmpctx,
							    struct amount_sat,
							    &fee),
					     type_to_string(tmpctx,
							    struct amount_msat,
							    &remainder));
				return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;
			}
			fee = fee_for_htlcs(channel,
					    committed,
					    adding,
					    removing,
					    !channel->opener);
			/* set fee output pointer if given */
			if (htlc_fee && amount_sat_greater(fee, *htlc_fee))
				*htlc_fee = fee;
			if (amount_msat_less_sat(remainder, fee)) {
				status_debug("Funder could not afford peer's fee %s with %s above reserve",
					     type_to_string(tmpctx,
							    struct amount_sat,
							    &fee),
					     type_to_string(tmpctx,
							    struct amount_msat,
							    &remainder));
				return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;
			}
		}
	}

	htlc_dust_amt = AMOUNT_MSAT(0);
	feerate = channel_feerate(channel, recipient);
	/* Note that we check for trimmed htlcs at an
	 * *accelerated* rate, so that future feerate changes
	 * don't suddenly surprise us */
	feerate_ceil = htlc_trim_feerate_ceiling(feerate);

	if (!htlc_dust(channel, committed,
		       adding, removing, recipient,
		       feerate_ceil, &htlc_dust_amt))
		return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;

	if (amount_msat_greater(htlc_dust_amt,
				channel->config[LOCAL].max_dust_htlc_exposure_msat)) {
		/* BOLT-919 #2:
		 * A node:
		 * - upon an incoming HTLC:
		 *   - if a HTLC's `amount_msat` is inferior to the
		 *   counterparty's `dust_limit_satoshis` plus the HTLC-timeout fee
		 *   at the `dust_buffer_feerate`: ...
		 *   - SHOULD fail this HTLC once it's committed
		 *   - SHOULD NOT reveal a preimage for this HTLC
		*/
		/* Note: Marking this as 'fail_immediate' and
		 * NOT returning an ERR will fail this HTLC
		 * once it's committed */
		htlc->fail_immediate = true;
		if (err_immediate_failures)
			return CHANNEL_ERR_DUST_FAILURE;
	}


	/* Also check the sender, as they'll eventually have the same
	 * constraint */
	htlc_dust_amt = AMOUNT_MSAT(0);
	feerate = channel_feerate(channel, sender);
	feerate_ceil = htlc_trim_feerate_ceiling(feerate);
	if (!htlc_dust(channel, committed, adding,
		       removing, sender, feerate_ceil,
		       &htlc_dust_amt))
		return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;

	if (amount_msat_greater(htlc_dust_amt,
				channel->config[LOCAL].max_dust_htlc_exposure_msat)) {
		htlc->fail_immediate = true;
		if (err_immediate_failures)
			return CHANNEL_ERR_DUST_FAILURE;
	}
	dump_htlc(htlc, "NEW:");
	htlc_map_add(channel->htlcs, tal_steal(channel, htlc));
	if (htlcp)
		*htlcp = htlc;

	return CHANNEL_ERR_ADD_OK;
}

enum channel_add_err channel_add_htlc(struct channel *channel,
				      enum side sender,
				      u64 id,
				      struct amount_msat amount,
				      u32 cltv_expiry,
				      const struct sha256 *payment_hash,
				      const u8 routing[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)],
				      const struct pubkey *blinding TAKES,
				      struct htlc **htlcp,
				      struct amount_sat *htlc_fee,
				      bool err_immediate_failures)
{
	enum htlc_state state;

	if (sender == LOCAL)
		state = SENT_ADD_HTLC;
	else
		state = RCVD_ADD_HTLC;

	/* BOLT #2:
	 * - MUST increase the value of `id` by 1 for each successive offer.
	 */
	/* This is a weak (bit cheap) check: */
	if (htlc_get(channel->htlcs, id+1, sender))
		status_broken("Peer sent out-of-order HTLC ids (is that you, old c-lightning node?)");

	return add_htlc(channel, state, id, amount, cltv_expiry,
			payment_hash, routing, blinding,
			htlcp, true, htlc_fee, err_immediate_failures);
}

struct htlc *channel_get_htlc(struct channel *channel, enum side sender, u64 id)
{
	return htlc_get(channel->htlcs, id, sender);
}

enum channel_remove_err channel_fulfill_htlc(struct channel *channel,
					     enum side owner,
					     u64 id,
					     const struct preimage *preimage,
					     struct htlc **htlcp)
{
	struct sha256 hash;
	struct htlc *htlc;

	htlc = channel_get_htlc(channel, owner, id);
	if (!htlc)
		return CHANNEL_ERR_NO_SUCH_ID;

	if (htlc->r)
		return CHANNEL_ERR_ALREADY_FULFILLED;

	sha256(&hash, preimage, sizeof(*preimage));
	/* BOLT #2:
	 *
	 *  - if the `payment_preimage` value in `update_fulfill_htlc`
	 *  doesn't SHA256 hash to the corresponding HTLC `payment_hash`:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (!sha256_eq(&hash, &htlc->rhash))
		return CHANNEL_ERR_BAD_PREIMAGE;

	htlc->r = tal_dup(htlc, struct preimage, preimage);

	/* BOLT #2:
	 *
	 *  - if the `id` does not correspond to an HTLC in its current
	 *    commitment transaction:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (!htlc_has(htlc, HTLC_FLAG(!htlc_owner(htlc), HTLC_F_COMMITTED))) {
		status_unusual("channel_fulfill_htlc: %"PRIu64" in state %s",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_UNCOMMITTED;
	}

	/* We enforce a stricter check, forcing state machine to be linear,
	 * based on: */
	/* BOLT #2:
	 *
	 * A node:
	 *...
	 *  - until the corresponding HTLC is irrevocably committed in both
	 *    sides' commitment transactions:
	 *    - MUST NOT send an `update_fulfill_htlc`, `update_fail_htlc`, or
	 *      `update_fail_malformed_htlc`.
	 */
	if (htlc->state == SENT_ADD_ACK_REVOCATION)
		htlc->state = RCVD_REMOVE_HTLC;
	else if (htlc->state == RCVD_ADD_ACK_REVOCATION)
		htlc->state = SENT_REMOVE_HTLC;
	else {
		status_unusual("channel_fulfill_htlc: %"PRIu64" in state %s",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_NOT_IRREVOCABLE;
	}

	dump_htlc(htlc, "FULFILL:");

	if (htlcp)
		*htlcp = htlc;

	return CHANNEL_ERR_REMOVE_OK;
}

enum channel_remove_err channel_fail_htlc(struct channel *channel,
					  enum side owner, u64 id,
					  struct htlc **htlcp)
{
	struct htlc *htlc;

	htlc = channel_get_htlc(channel, owner, id);
	if (!htlc)
		return CHANNEL_ERR_NO_SUCH_ID;

	/* BOLT #2:
	 *
	 * A receiving node:
	 *   - if the `id` does not correspond to an HTLC in its current
	 *     commitment transaction:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (!htlc_has(htlc, HTLC_FLAG(!htlc_owner(htlc), HTLC_F_COMMITTED))) {
		status_unusual("channel_fail_htlc: %"PRIu64" in state %s",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_UNCOMMITTED;
	}

	/* FIXME: Technically, they can fail this before we're committed to
	 * it.  This implies a non-linear state machine. */
	if (htlc->state == SENT_ADD_ACK_REVOCATION)
		htlc->state = RCVD_REMOVE_HTLC;
	else if (htlc->state == RCVD_ADD_ACK_REVOCATION)
		htlc->state = SENT_REMOVE_HTLC;
	else {
		status_unusual("channel_fail_htlc: %"PRIu64" in state %s",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_NOT_IRREVOCABLE;
	}

	dump_htlc(htlc, "FAIL:");
	if (htlcp)
		*htlcp = htlc;
	return CHANNEL_ERR_REMOVE_OK;
}

static void htlc_incstate(struct channel *channel,
			  struct htlc *htlc,
			  enum side sidechanged,
			  struct balance owed[NUM_SIDES])
{
	int preflags, postflags;
	const int committed_f = HTLC_FLAG(sidechanged, HTLC_F_COMMITTED);

	status_debug("htlc %"PRIu64": %s->%s", htlc->id,
		     htlc_state_name(htlc->state),
		     htlc_state_name(htlc->state+1));

	preflags = htlc_state_flags(htlc->state);
	postflags = htlc_state_flags(htlc->state + 1);
	/* You can't change sides. */
	assert((preflags & (HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER))
	       == (postflags & (HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER)));

	htlc->state++;

	/* If we've added or removed, adjust balances. */
	if (!(preflags & committed_f) && (postflags & committed_f)) {
		status_debug("htlc added %s: local %"PRId64" remote %"PRId64,
			     side_to_str(sidechanged),
			     owed[LOCAL].msat, owed[REMOTE].msat);
		balance_add_htlc(&owed[LOCAL], htlc, LOCAL);
		balance_add_htlc(&owed[REMOTE], htlc, REMOTE);
		status_debug("-> local %"PRId64" remote %"PRId64,
			     owed[LOCAL].msat, owed[REMOTE].msat);
	} else if ((preflags & committed_f) && !(postflags & committed_f)) {
		status_debug("htlc added %s: local %"PRId64" remote %"PRId64,
			     side_to_str(sidechanged),
			     owed[LOCAL].msat, owed[REMOTE].msat);
		balance_remove_htlc(&owed[LOCAL], htlc, LOCAL);
		balance_remove_htlc(&owed[REMOTE], htlc, REMOTE);
		status_debug("-> local %"PRId64" remote %"PRId64,
			     owed[LOCAL].msat, owed[REMOTE].msat);
	}
}

/* Returns true if a change was made. */
static bool fee_incstate(struct channel *channel,
			 enum side sidechanged,
			 enum htlc_state hstate)
{
	int preflags, postflags;

	preflags = htlc_state_flags(hstate);
	postflags = htlc_state_flags(hstate + 1);

	/* You can't change sides. */
	assert((preflags & (HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER))
	       == (postflags & (HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER)));

	/* These only advance through ADDING states. */
	if (!(htlc_state_flags(hstate) & HTLC_ADDING))
		return false;

	if (!inc_fee_state(channel->fee_states, hstate))
		return false;

	status_debug("Feerate: %s->%s %s now %u",
		     htlc_state_name(hstate),
		     htlc_state_name(hstate+1),
		     side_to_str(sidechanged),
		     *channel->fee_states->feerate[hstate+1]);
	return true;
}

static bool blockheight_incstate(struct channel *channel,
				 enum side sidechanged,
				 enum htlc_state hstate)
{
	int preflags, postflags;

	preflags = htlc_state_flags(hstate);
	postflags = htlc_state_flags(hstate + 1);

	/* You can't change sides. */
	assert((preflags & (HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER))
	       == (postflags & (HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER)));

	/* These only advance through ADDING states. */
	if (!(htlc_state_flags(hstate) & HTLC_ADDING))
		return false;

	if (!inc_height_state(channel->blockheight_states, hstate))
		return false;

	status_debug("Blockheight: %s->%s %s now %u",
		     htlc_state_name(hstate),
		     htlc_state_name(hstate+1),
		     side_to_str(sidechanged),
		     *channel->blockheight_states->height[hstate+1]);
	return true;
}

/* Returns flags which were changed. */
static int change_htlcs(struct channel *channel,
			enum side sidechanged,
			const enum htlc_state *htlc_states,
			size_t n_hstates,
			const struct htlc ***htlcs,
			const char *prefix)
{
	struct htlc_map_iter it;
	struct htlc *h;
	int cflags = 0;
	int i;
	struct balance owed[NUM_SIDES];

	for (i = 0; i < NUM_SIDES; i++)
		to_balance(&owed[i], channel->view[sidechanged].owed[i]);

	for (h = htlc_map_first(channel->htlcs, &it);
	     h;
	     h = htlc_map_next(channel->htlcs, &it)) {
		for (i = 0; i < n_hstates; i++) {
			if (h->state == htlc_states[i]) {
				htlc_incstate(channel, h, sidechanged, owed);
				if (htlc_is_dead(h)) {
					htlc_map_delval(channel->htlcs, &it);
					tal_steal(htlcs ? *htlcs : tmpctx, h);
				}
				dump_htlc(h, prefix);
				htlc_arr_append(htlcs, h);
				cflags |= (htlc_state_flags(htlc_states[i])
					   ^ htlc_state_flags(h->state));
				break;
			}
		}
	}

	for (i = 0; i < NUM_SIDES; i++) {
		if (!balance_ok(&owed[i], &channel->view[sidechanged].owed[i])) {
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s: %s balance underflow: %s -> %"PRId64,
				      side_to_str(sidechanged),
				      side_to_str(i),
				      type_to_string(tmpctx, struct amount_msat,
						     &channel->view[sidechanged].owed[i]),
				      owed[i].msat);
		}
	}

	/* Update fees and blockheight (do backwards, to avoid
	 * double-increment!). */
	for (i = n_hstates - 1; i >= 0; i--) {
		if (fee_incstate(channel, sidechanged, htlc_states[i]))
			cflags |= (htlc_state_flags(htlc_states[i])
				   ^ htlc_state_flags(htlc_states[i]+1));

		if (blockheight_incstate(channel, sidechanged, htlc_states[i]))
			cflags |= (htlc_state_flags(htlc_states[i])
				   ^ htlc_state_flags(htlc_states[i]+1));
	}

	return cflags;
}

/* FIXME: The sender's requirements are *implied* by this, not stated! */
/* BOLT #2:
 *
 * A receiving node:
 *...
 *   - if the sender cannot afford the new fee rate on the receiving node's
 *     current commitment transaction:
 *     - SHOULD send a `warning` and close the connection, or send an
 *       `error` and fail the channel.
 */
u32 approx_max_feerate(const struct channel *channel)
{
	size_t num;
	u64 weight;
	struct amount_sat avail;
	const struct htlc **committed, **adding, **removing;
	bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	gather_htlcs(tmpctx, channel, !channel->opener,
		     &committed, &removing, &adding);

	/* Assume none are trimmed; this gives lower bound on feerate. */
	num = tal_count(committed) + tal_count(adding) - tal_count(removing);

	weight = commit_tx_base_weight(num, option_anchor_outputs, option_anchors_zero_fee_htlc_tx);

	/* Available is their view */
	avail = amount_msat_to_sat_round_down(channel->view[!channel->opener].owed[channel->opener]);

	/* BOLT #3:
	 * If `option_anchors` applies to the commitment
	 * transaction, also subtract two times the fixed anchor size
	 * of 330 sats from the funder (either `to_local` or
	 * `to_remote`).
	 */
	if ((option_anchor_outputs || option_anchors_zero_fee_htlc_tx)
	    && !amount_sat_sub(&avail, avail, AMOUNT_SAT(660))) {
		avail = AMOUNT_SAT(0);
	} else {
		/* We should never go below reserve. */
		if (!amount_sat_sub(&avail, avail,
				    channel->config[!channel->opener].channel_reserve))
		avail = AMOUNT_SAT(0);
	}

	return avail.satoshis / weight * 1000; /* Raw: once-off reverse feerate*/
}

/* Is the sum of trimmed htlcs, as this new feerate, above our
 * max allowed htlc dust limit? */
static struct amount_msat htlc_calculate_dust(const struct channel *channel,
					      u32 feerate_per_kw,
					      enum side side)
{
	const struct htlc **committed, **adding, **removing;
	struct amount_msat acc_dust = AMOUNT_MSAT(0);

	gather_htlcs(tmpctx, channel, side,
		     &committed, &removing, &adding);

	htlc_dust(channel, committed, adding, removing,
		  side, feerate_per_kw, &acc_dust);

	return acc_dust;
}

bool htlc_dust_ok(const struct channel *channel,
		  u32 feerate_per_kw,
		  enum side side)
{
	struct amount_msat total_dusted;

	total_dusted = htlc_calculate_dust(channel, feerate_per_kw, side);

	return amount_msat_greater_eq(
		channel->config[LOCAL].max_dust_htlc_exposure_msat,
		total_dusted);
}

bool can_opener_afford_feerate(const struct channel *channel, u32 feerate_per_kw)
{
	struct amount_sat needed, fee;
	struct amount_sat dust_limit = channel->config[!channel->opener].dust_limit;
	size_t untrimmed;
	const struct htlc **committed, **adding, **removing;
	bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	gather_htlcs(tmpctx, channel, !channel->opener,
		     &committed, &removing, &adding);

	untrimmed = commit_tx_num_untrimmed(committed, feerate_per_kw, dust_limit,
					    option_anchor_outputs,
					    option_anchors_zero_fee_htlc_tx,
					    !channel->opener)
			+ commit_tx_num_untrimmed(adding, feerate_per_kw, dust_limit,
						  option_anchor_outputs,
						  option_anchors_zero_fee_htlc_tx,
						  !channel->opener)
			- commit_tx_num_untrimmed(removing, feerate_per_kw, dust_limit,
						  option_anchor_outputs,
						  option_anchors_zero_fee_htlc_tx,
						  !channel->opener);

	fee = commit_tx_base_fee(feerate_per_kw, untrimmed,
				 option_anchor_outputs,
				 option_anchors_zero_fee_htlc_tx);

	/* BOLT #3:
	 * If `option_anchors` applies to the commitment
	 * transaction, also subtract two times the fixed anchor size
	 * of 330 sats from the funder (either `to_local` or
	 * `to_remote`).
	 */
	if ((option_anchor_outputs || option_anchors_zero_fee_htlc_tx)
	    && !amount_sat_add(&fee, fee, AMOUNT_SAT(660)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot add 660 sats to %s for anchor",
			      type_to_string(tmpctx, struct amount_sat,
					     &fee));

	/* BOLT #2:
	 *
	 *   - if the sender cannot afford the new fee rate on the receiving
	 *     node's current commitment transaction:
	 *     - SHOULD send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	/* Note: sender == opener */

	/* How much does it think it has?  Must be >= reserve + fee */
	if (!amount_sat_add(&needed, fee,
			    channel->config[!channel->opener].channel_reserve))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot add fee %s and reserve %s",
			      type_to_string(tmpctx, struct amount_sat,
					     &fee),
			      type_to_string(tmpctx, struct amount_sat,
					     &channel->config[!channel->opener].channel_reserve));

	status_debug("We need %s at feerate %u for %zu untrimmed htlcs: we have %s/%s",
		     type_to_string(tmpctx, struct amount_sat, &needed),
		     feerate_per_kw, untrimmed,
		     type_to_string(tmpctx, struct amount_msat,
				    &channel->view[LOCAL].owed[channel->opener]),
		     type_to_string(tmpctx, struct amount_msat,
				    &channel->view[REMOTE].owed[channel->opener]));
	return amount_msat_greater_eq_sat(channel->view[!channel->opener].owed[channel->opener],
					  needed);
}

bool channel_update_feerate(struct channel *channel, u32 feerate_per_kw)
{
	if (!can_opener_afford_feerate(channel, feerate_per_kw))
		return false;

	/* BOLT-919 #2:
	 * - if the `dust_balance_on_holder_tx` at the
	 *   new `dust_buffer_feerate` is superior to
	 *   the `max_dust_htlc_exposure_msat`:
	 *   ...
	 *   - MAY fail the channel
	 */
	if (!htlc_dust_ok(channel, feerate_per_kw, REMOTE) ||
	    !htlc_dust_ok(channel, feerate_per_kw, LOCAL))
		return false;

	status_debug("Setting %s feerate to %u",
		     side_to_str(!channel->opener), feerate_per_kw);

	start_fee_update(channel->fee_states, channel->opener, feerate_per_kw);
	return true;
}

void channel_update_blockheight(struct channel *channel,
				u32 blockheight)
{
	status_debug("Setting %s blockheight to %u",
		     side_to_str(!channel->opener), blockheight);

	start_height_update(channel->blockheight_states, channel->opener,
			    blockheight);
}

bool channel_sending_commit(struct channel *channel,
			    const struct htlc ***htlcs)
{
	int change;
	const enum htlc_state states[] = { SENT_ADD_HTLC,
					   SENT_REMOVE_REVOCATION,
					   SENT_ADD_REVOCATION,
					   SENT_REMOVE_HTLC };
	status_debug("Trying commit");

	change = change_htlcs(channel, REMOTE, states, ARRAY_SIZE(states),
			      htlcs, "sending_commit");
	if (!change)
		return false;

	return true;
}

bool channel_rcvd_revoke_and_ack(struct channel *channel,
				 const struct htlc ***htlcs)
{
	int change;
	const enum htlc_state states[] = { SENT_ADD_COMMIT,
					   SENT_REMOVE_ACK_COMMIT,
					   SENT_ADD_ACK_COMMIT,
					   SENT_REMOVE_COMMIT };

	status_debug("Received revoke_and_ack");
	change = change_htlcs(channel, LOCAL, states, ARRAY_SIZE(states),
			      htlcs, "rcvd_revoke_and_ack");

	/* Their ack can queue changes on our side. */
	return (change & HTLC_LOCAL_F_PENDING);
}

/* FIXME: We can actually merge these two... */
bool channel_rcvd_commit(struct channel *channel, const struct htlc ***htlcs)
{
	int change;
	const enum htlc_state states[] = { RCVD_ADD_REVOCATION,
					   RCVD_REMOVE_HTLC,
					   RCVD_ADD_HTLC,
					   RCVD_REMOVE_REVOCATION };

	status_debug("Received commit");
	change = change_htlcs(channel, LOCAL, states, ARRAY_SIZE(states),
			      htlcs, "rcvd_commit");
	if (!change)
		return false;
	return true;
}

bool channel_sending_revoke_and_ack(struct channel *channel)
{
	int change;
	const enum htlc_state states[] = { RCVD_ADD_ACK_COMMIT,
					   RCVD_REMOVE_COMMIT,
					   RCVD_ADD_COMMIT,
					   RCVD_REMOVE_ACK_COMMIT };
	status_debug("Sending revoke_and_ack");
	change = change_htlcs(channel, REMOTE, states, ARRAY_SIZE(states), NULL,
			      "sending_revoke_and_ack");

	/* Our ack can queue changes on their side. */
	return (change & HTLC_REMOTE_F_PENDING);
}

static inline bool any_htlc_is_dead(const struct channel *channel)
{
	struct htlc_map_iter it;
	const struct htlc *htlc;

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		if (htlc_is_dead(htlc))
			return true;
	}
	return false;
}

size_t num_channel_htlcs(const struct channel *channel)
{
	assert(!any_htlc_is_dead(channel));
	return htlc_map_count(channel->htlcs);
}

static bool adjust_balance(struct balance view_owed[NUM_SIDES][NUM_SIDES],
			   struct htlc *htlc)
{
	enum side side;

	for (side = 0; side < NUM_SIDES; side++) {
		/* Did it ever add it? */
		if (!htlc_has(htlc, HTLC_FLAG(side, HTLC_F_WAS_COMMITTED)))
			continue;

		/* Add it. */
		balance_add_htlc(&view_owed[side][LOCAL], htlc, LOCAL);
		balance_add_htlc(&view_owed[side][REMOTE], htlc, REMOTE);

		/* If it is no longer committed, remove it (depending
		 * on fail || fulfill). */
		if (htlc_has(htlc, HTLC_FLAG(side, HTLC_F_COMMITTED)))
			continue;

		if (!htlc->failed && !htlc->r) {
			status_broken("%s HTLC %"PRIu64
				      " %s neither fail nor fulfill?",
				      htlc_state_owner(htlc->state) == LOCAL
				      ? "out" : "in",
				      htlc->id,
				      htlc_state_name(htlc->state));
			return false;
		}
		balance_remove_htlc(&view_owed[side][LOCAL], htlc, LOCAL);
		balance_remove_htlc(&view_owed[side][REMOTE], htlc, REMOTE);
	}
	return true;
}

bool pending_updates(const struct channel *channel,
		     enum side side,
		     bool uncommitted_ok)
{
	struct htlc_map_iter it;
	const struct htlc *htlc;

	/* Initiator might have fee changes or blockheight updates in play. */
	if (side == channel->opener) {
		if (!feerate_changes_done(channel->fee_states, uncommitted_ok))
			return true;

		if (!blockheight_changes_done(channel->blockheight_states,
					      uncommitted_ok))
			return true;
	}

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		int flags = htlc_state_flags(htlc->state);

		/* If it's still being added, its owner added it. */
		if (flags & HTLC_ADDING) {
			/* It might be OK if it's added, but not committed */
			if (uncommitted_ok
			    && (flags & HTLC_FLAG(!side, HTLC_F_PENDING)))
				continue;
			if (htlc_owner(htlc) == side)
				return true;
		/* If it's being removed, non-owner removed it */
		} else if (htlc_state_flags(htlc->state) & HTLC_REMOVING) {
			/* It might be OK if it's removed, but not committed */
			if (uncommitted_ok
			    && (flags & HTLC_FLAG(!side, HTLC_F_PENDING)))
				continue;
			if (htlc_owner(htlc) != side)
				return true;
		}
	}

	return false;
}

bool channel_force_htlcs(struct channel *channel,
			 const struct existing_htlc **htlcs)
{
	struct balance view_owed[NUM_SIDES][NUM_SIDES];

	/* You'd think, since we traverse HTLCs in ID order, this would never
	 * go negative.  But this ignores the fact that HTLCs ids from each
	 * side have no correlation with each other.  Copy into struct balance,
	 * to allow transient underflow. */
	for (int view = 0; view < NUM_SIDES; view++) {
		for (int side = 0; side < NUM_SIDES; side++) {
			to_balance(&view_owed[view][side],
				   channel->view[view].owed[side]);
		}
	}

	for (size_t i = 0; i < tal_count(htlcs); i++) {
		enum channel_add_err e;
		struct htlc *htlc;

		status_debug("Restoring HTLC %zu/%zu:"
			     " id=%"PRIu64" amount=%s cltv=%u"
			     " payment_hash=%s %s",
			     i, tal_count(htlcs),
			     htlcs[i]->id,
			     type_to_string(tmpctx, struct amount_msat,
					    &htlcs[i]->amount),
			     htlcs[i]->cltv_expiry,
			     type_to_string(tmpctx, struct sha256,
					    &htlcs[i]->payment_hash),
			     htlcs[i]->payment_preimage ? "(have preimage)"
			     : htlcs[i]->failed ? "(failed)" : "");

		e = add_htlc(channel, htlcs[i]->state,
			     htlcs[i]->id, htlcs[i]->amount,
			     htlcs[i]->cltv_expiry,
			     &htlcs[i]->payment_hash,
			     htlcs[i]->onion_routing_packet,
			     htlcs[i]->blinding,
			     &htlc, false, NULL, false);
		if (e != CHANNEL_ERR_ADD_OK) {
			status_broken("%s HTLC %"PRIu64" failed error %u",
				     htlc_state_owner(htlcs[i]->state) == LOCAL
				     ? "out" : "in", htlcs[i]->id, e);
			return false;
		}
		if (htlcs[i]->payment_preimage)
			htlc->r = tal_dup(htlc, struct preimage,
					  htlcs[i]->payment_preimage);
		if (htlcs[i]->failed)
			htlc->failed = tal_steal(htlc, htlcs[i]->failed);

		if (!adjust_balance(view_owed, htlc))
			return false;
	}

	/* Convert back and check */
	for (int view = 0; view < NUM_SIDES; view++) {
		for (int side = 0; side < NUM_SIDES; side++) {
			if (!balance_ok(&view_owed[view][side],
					&channel->view[view].owed[side])) {
				status_broken("view %s[%s] balance underflow:"
					      " %"PRId64,
					      side_to_str(view),
					      side_to_str(side),
					      view_owed[view][side].msat);
				return false;
			}
		}
	}

	return true;
}

const char *channel_add_err_name(enum channel_add_err e)
{
	static char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];

	for (size_t i = 0; enum_channel_add_err_names[i].name; i++) {
		if (enum_channel_add_err_names[i].v == e)
			return enum_channel_add_err_names[i].name;
	}
	snprintf(invalidbuf, sizeof(invalidbuf), "INVALID %i", e);
	return invalidbuf;
}

const char *channel_remove_err_name(enum channel_remove_err e)
{
	static char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];

	for (size_t i = 0; enum_channel_remove_err_names[i].name; i++) {
		if (enum_channel_remove_err_names[i].v == e)
			return enum_channel_remove_err_names[i].name;
	}
	snprintf(invalidbuf, sizeof(invalidbuf), "INVALID %i", e);
	return invalidbuf;
}
