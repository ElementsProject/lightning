#include <assert.h>
#include <bitcoin/preimage.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/commit_tx.h>
#include <channeld/full_channel.h>
#include <common/channel_config.h>
#include <common/htlc.h>
#include <common/htlc_tx.h>
#include <common/htlc_wire.h>
#include <common/key_derive.h>
#include <common/keyset.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
  /* Needs to be at end, since it doesn't include its own hdrs */
  #include "gen_full_channel_error_names.h"

struct channel *new_full_channel(const tal_t *ctx,
				 const struct bitcoin_txid *funding_txid,
				 unsigned int funding_txout,
				 u64 funding_satoshis,
				 u64 local_msatoshi,
				 const u32 feerate_per_kw[NUM_SIDES],
				 const struct channel_config *local,
				 const struct channel_config *remote,
				 const struct basepoints *local_basepoints,
				 const struct basepoints *remote_basepoints,
				 const struct pubkey *local_funding_pubkey,
				 const struct pubkey *remote_funding_pubkey,
				 enum side funder)
{
	struct channel *channel = new_initial_channel(ctx, funding_txid,
						      funding_txout,
						      funding_satoshis,
						      local_msatoshi,
						      feerate_per_kw[LOCAL],
						      local, remote,
						      local_basepoints,
						      remote_basepoints,
						      local_funding_pubkey,
						      remote_funding_pubkey,
						      funder);

	if (channel) {
		/* Feerates can be different. */
		channel->view[REMOTE].feerate_per_kw = feerate_per_kw[REMOTE];
		channel->htlcs = tal(channel, struct htlc_map);
		htlc_map_init(channel->htlcs);
		tal_add_destructor(channel->htlcs, htlc_map_clear);
	}
	return channel;
}

static void htlc_arr_append(const struct htlc ***arr, const struct htlc *htlc)
{
	size_t n;
	if (!arr)
		return;
	n = tal_count(*arr);
	tal_resize(arr, n+1);
	(*arr)[n] = htlc;
}

/* What does adding the HTLC do to the balance for this side */
static s64 balance_adding_htlc(const struct htlc *htlc, enum side side)
{
	if (htlc_owner(htlc) == side)
		return -htlc->msatoshi;
	return 0;
}

/* What does removing the HTLC do to the balance for this side */
static s64 balance_removing_htlc(const struct htlc *htlc, enum side side)
{
	enum side paid_to;

	/* Fulfilled HTLCs are paid to recipient, otherwise returns to owner */
	if (htlc->r)
		paid_to = !htlc_owner(htlc);
	else
		paid_to = htlc_owner(htlc);

	if (side == paid_to)
		return htlc->msatoshi;
	return 0;
}

static void dump_htlc(const struct htlc *htlc, const char *prefix)
{
	enum htlc_state remote_state;

	if (htlc->state <= RCVD_REMOVE_ACK_REVOCATION)
		remote_state = htlc->state + 10;
	else
		remote_state = htlc->state - 10;

	status_trace("%s: HTLC %s %"PRIu64" = %s/%s %s",
		     prefix,
		     htlc_owner(htlc) == LOCAL ? "LOCAL" : "REMOTE",
		     htlc->id,
		     htlc_state_name(htlc->state),
		     htlc_state_name(remote_state),
		     htlc->r ? "FULFILLED" : htlc->fail ? "FAILED" :
		     htlc->failcode
		     ? tal_fmt(tmpctx, "FAILCODE:%u", htlc->failcode) : "");
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
 */
static void gather_htlcs(const tal_t *ctx,
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

	*committed = tal_arr(ctx, const struct htlc *, 0);
	if (pending_removal)
		*pending_removal = tal_arr(ctx, const struct htlc *, 0);
	if (pending_addition)
		*pending_addition = tal_arr(ctx, const struct htlc *, 0);

	if (!channel->htlcs)
		return;

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		if (htlc_has(htlc, committed_flag)) {
			htlc_arr_append(committed, htlc);
			if (htlc_has(htlc, pending_flag))
				htlc_arr_append(pending_removal, htlc);
		} else if (htlc_has(htlc, pending_flag))
			htlc_arr_append(pending_addition, htlc);
	}
}

static u64 total_offered_msatoshis(const struct htlc **htlcs, enum side side)
{
	size_t i;
	u64 total = 0;

	for (i = 0; i < tal_count(htlcs); i++) {
		if (htlc_owner(htlcs[i]) == side)
			total += htlcs[i]->msatoshi;
	}
	return total;
}

static void add_htlcs(struct bitcoin_tx ***txs,
		      const u8 ***wscripts,
		      const struct htlc **htlcmap,
		      const struct channel *channel,
		      const struct keyset *keyset,
		      enum side side)
{
	size_t i, n;
	struct bitcoin_txid txid;
	u32 feerate_per_kw = channel->view[side].feerate_per_kw;

	/* Get txid of commitment transaction */
	bitcoin_txid((*txs)[0], &txid);

	for (i = 0; i < tal_count(htlcmap); i++) {
		const struct htlc *htlc = htlcmap[i];
		struct bitcoin_tx *tx;
		u8 *wscript;

		if (!htlc)
			continue;

		if (htlc_owner(htlc) == side) {
			tx = htlc_timeout_tx(*txs, &txid, i,
					     htlc->msatoshi,
					     htlc->expiry.locktime,
					     to_self_delay(channel, side),
					     feerate_per_kw,
					     keyset);
			wscript	= bitcoin_wscript_htlc_offer(*wscripts,
						     &keyset->self_htlc_key,
						     &keyset->other_htlc_key,
						     &htlc->rhash,
						     &keyset->self_revocation_key);
		} else {
			tx = htlc_success_tx(*txs, &txid, i,
					     htlc->msatoshi,
					     to_self_delay(channel, side),
					     feerate_per_kw,
					     keyset);
			wscript	= bitcoin_wscript_htlc_receive(*wscripts,
						       &htlc->expiry,
						       &keyset->self_htlc_key,
						       &keyset->other_htlc_key,
						       &htlc->rhash,
						       &keyset->self_revocation_key);
		}

		/* Append to array. */
		n = tal_count(*txs);
		assert(n == tal_count(*wscripts));

		tal_resize(wscripts, n+1);
		tal_resize(txs, n+1);
		(*wscripts)[n] = wscript;
		(*txs)[n] = tx;
	}
}

/* FIXME: We could cache these. */
struct bitcoin_tx **channel_txs(const tal_t *ctx,
				const struct htlc ***htlcmap,
				const u8 ***wscripts,
				const struct channel *channel,
				const struct pubkey *per_commitment_point,
				u64 commitment_number,
				enum side side)
{
	struct bitcoin_tx **txs;
	const struct htlc **committed;
	struct keyset keyset;

	if (!derive_keyset(per_commitment_point,
			   &channel->basepoints[side],
			   &channel->basepoints[!side],
			   &keyset))
		return NULL;

	/* Figure out what @side will already be committed to. */
	gather_htlcs(ctx, channel, side, &committed, NULL, NULL);

	txs = tal_arr(ctx, struct bitcoin_tx *, 1);
	txs[0] = commit_tx(ctx, &channel->funding_txid,
		       channel->funding_txout,
		       channel->funding_msat / 1000,
		       channel->funder,
		       to_self_delay(channel, side),
		       &keyset,
		       channel->view[side].feerate_per_kw,
		       dust_limit_satoshis(channel, side),
		       channel->view[side].owed_msat[side],
		       channel->view[side].owed_msat[!side],
		       committed,
		       htlcmap,
		       commitment_number ^ channel->commitment_number_obscurer,
		       side);

	*wscripts = tal_arr(ctx, const u8 *, 1);
	(*wscripts)[0] = bitcoin_redeem_2of2(*wscripts,
					     &channel->funding_pubkey[side],
					     &channel->funding_pubkey[!side]);

	add_htlcs(&txs, wscripts, *htlcmap, channel, &keyset, side);

	tal_free(committed);
	return txs;
}

static enum channel_add_err add_htlc(struct channel *channel,
				     enum htlc_state state,
				     u64 id, u64 msatoshi, u32 cltv_expiry,
				     const struct sha256 *payment_hash,
				     const u8 routing[TOTAL_PACKET_SIZE],
				     struct htlc **htlcp,
				     bool enforce_aggregate_limits)
{
	struct htlc *htlc, *old;
	s64 msat_in_htlcs, fee_msat, balance_msat;
	enum side sender = htlc_state_owner(state), recipient = !sender;
	const struct htlc **committed, **adding, **removing;
	const struct channel_view *view;
	size_t i;

	htlc = tal(tmpctx, struct htlc);

	htlc->id = id;
	htlc->msatoshi = msatoshi;
	htlc->state = state;
	htlc->shared_secret = NULL;

	/* FIXME: Change expiry to simple u32 */

	/* BOLT #2:
	 *
	 * A receiving node:
	 *...
	 *  - if sending node sets `cltv_expiry` to greater or equal to
	 *    500000000:
	 *    - SHOULD fail the channel.
	 */
	if (!blocks_to_abs_locktime(cltv_expiry, &htlc->expiry)) {
		return CHANNEL_ERR_INVALID_EXPIRY;
	}

	htlc->rhash = *payment_hash;
	htlc->fail = NULL;
	htlc->failcode = 0;
	htlc->failed_scid = NULL;
	htlc->r = NULL;
	htlc->routing = tal_dup_arr(htlc, u8, routing, TOTAL_PACKET_SIZE, 0);

	old = htlc_get(channel->htlcs, htlc->id, htlc_owner(htlc));
	if (old) {
		if (old->state != htlc->state
		    || old->msatoshi != htlc->msatoshi
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
	 *    - SHOULD fail the channel.
	 */
	if (htlc->msatoshi == 0) {
		return CHANNEL_ERR_HTLC_BELOW_MINIMUM;
	}
	if (htlc->msatoshi < htlc_minimum_msat(channel, recipient)) {
		return CHANNEL_ERR_HTLC_BELOW_MINIMUM;
	}

	/* BOLT #2:
	 *
	 * - for channels with `chain_hash` identifying the Bitcoin blockchain:
	 *    - MUST set the four most significant bytes of `amount_msat` to 0.
	 */
	if (htlc->msatoshi & 0xFFFFFFFF00000000ULL) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

	/* Figure out what receiver will already be committed to. */
	gather_htlcs(tmpctx, channel, recipient, &committed, &removing, &adding);
	htlc_arr_append(&adding, htlc);

	/* BOLT #2:
	 *
	 *   - if a sending node adds more than its `max_accepted_htlcs` HTLCs to
	 *     its local commitment transaction...
	 *     - SHOULD fail the channel.
	 */
	if (enforce_aggregate_limits
	    && tal_count(committed) - tal_count(removing) + tal_count(adding)
	    > max_accepted_htlcs(channel, recipient)) {
		return CHANNEL_ERR_TOO_MANY_HTLCS;
	}

	msat_in_htlcs = total_offered_msatoshis(committed, htlc_owner(htlc))
		- total_offered_msatoshis(removing, htlc_owner(htlc))
		+ total_offered_msatoshis(adding, htlc_owner(htlc));

	/* BOLT #2:
	 *
	 *   - if a sending node... adds more than its
	 *     `max_htlc_value_in_flight_msat` worth of offered HTLCs to its
	 *     local commitment transaction:
	 *     - SHOULD fail the channel.
	 */
	if (enforce_aggregate_limits
	    && msat_in_htlcs > max_htlc_value_in_flight_msat(channel, recipient)) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

	/* BOLT #2:
	 *
	 * A receiving node:
	 *...
	 *  - receiving an `amount_msat` that the sending node cannot afford at
	 *    the current `feerate_per_kw` (while maintaining its channel
	 *    reserve):
	 *    - SHOULD fail the channel.
	 */
	if (channel->funder == htlc_owner(htlc)) {
		u32 feerate = view->feerate_per_kw;
		u64 dust = dust_limit_satoshis(channel, recipient);
		size_t untrimmed;

		untrimmed = commit_tx_num_untrimmed(committed, feerate, dust,
						    recipient)
			+ commit_tx_num_untrimmed(adding, feerate, dust,
						  recipient)
			- commit_tx_num_untrimmed(removing, feerate, dust,
						  recipient);

		fee_msat = commit_tx_base_fee(feerate, untrimmed);
	} else
		fee_msat = 0;

	assert(fee_msat >= 0);

	/* Figure out what balance sender would have after applying all
	 * pending changes. */
	balance_msat = view->owed_msat[sender];

	assert(balance_msat >= 0);
	for (i = 0; i < tal_count(removing); i++)
		balance_msat += balance_removing_htlc(removing[i], sender);
	assert(balance_msat >= 0);
	for (i = 0; i < tal_count(adding); i++)
		balance_msat += balance_adding_htlc(adding[i], sender);

	/* This is a little subtle:
	 *
	 * The change is being applied to the receiver but it will
	 * come back to the sender after revoke_and_ack.  So the check
	 * here is that the balance to the sender doesn't go below the
	 * sender's reserve. */
	if (enforce_aggregate_limits
	    && balance_msat - fee_msat < (s64)channel_reserve_msat(channel, sender)) {
		status_trace("balance = %"PRIu64
			     ", fee is %"PRIu64
			     ", reserve is %"PRIu64,
			     balance_msat, fee_msat,
			     channel_reserve_msat(channel, sender));
		return CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;
	}

	dump_htlc(htlc, "NEW:");
	htlc_map_add(channel->htlcs, tal_steal(channel, htlc));
	if (htlcp)
		*htlcp = htlc;

	/* This is simply setting changes_pending[receiver] unless it's
	 * an exotic state (i.e. channel_force_htlcs) */
	if (htlc_state_flags(htlc->state) & HTLC_LOCAL_F_PENDING)
		channel->changes_pending[LOCAL] = true;
	if (htlc_state_flags(htlc->state) & HTLC_REMOTE_F_PENDING)
		channel->changes_pending[REMOTE] = true;

	return CHANNEL_ERR_ADD_OK;
}

enum channel_add_err channel_add_htlc(struct channel *channel,
				      enum side sender,
				      u64 id,
				      u64 msatoshi,
				      u32 cltv_expiry,
				      const struct sha256 *payment_hash,
				      const u8 routing[TOTAL_PACKET_SIZE],
				      struct htlc **htlcp)
{
	enum htlc_state state;

	if (sender == LOCAL)
		state = SENT_ADD_HTLC;
	else
		state = RCVD_ADD_HTLC;

	/* FIXME: check expiry etc. against config. */
	return add_htlc(channel, state, id, msatoshi, cltv_expiry,
			payment_hash, routing, htlcp, true);
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
	 *    - MUST fail the channel.
	 */
	if (!sha256_eq(&hash, &htlc->rhash))
		return CHANNEL_ERR_BAD_PREIMAGE;

	htlc->r = tal_dup(htlc, struct preimage, preimage);

	/* BOLT #2:
	 *
	 *  - if the `id` does not correspond to an HTLC in its current
	 *    commitment transaction:
	 *    - MUST fail the channel.
	 */
	if (!htlc_has(htlc, HTLC_FLAG(!htlc_owner(htlc), HTLC_F_COMMITTED))) {
		status_trace("channel_fulfill_htlc: %"PRIu64" in state %s",
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
		status_trace("channel_fulfill_htlc: %"PRIu64" in state %s",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_NOT_IRREVOCABLE;
	}
	/* The HTLC owner is the recipient of the fulfillment. */
	channel->changes_pending[owner] = true;

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
	 *     - MUST fail the channel.
	 */
	if (!htlc_has(htlc, HTLC_FLAG(!htlc_owner(htlc), HTLC_F_COMMITTED))) {
		status_trace("channel_fail_htlc: %"PRIu64" in state %s",
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
		status_trace("channel_fail_htlc: %"PRIu64" in state %s",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_NOT_IRREVOCABLE;
	}
	/* The HTLC owner is the recipient of the failure. */
	channel->changes_pending[owner] = true;

	dump_htlc(htlc, "FAIL:");
	if (htlcp)
		*htlcp = htlc;
	return CHANNEL_ERR_REMOVE_OK;
}

static void htlc_incstate(struct channel *channel,
			  struct htlc *htlc,
			  enum side sidechanged)
{
	int preflags, postflags;
	const int committed_f = HTLC_FLAG(sidechanged, HTLC_F_COMMITTED);

	status_trace("htlc %"PRIu64": %s->%s", htlc->id,
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
		status_trace("htlc added %s: local %+"PRIi64" remote %+"PRIi64,
			     side_to_str(sidechanged),
			     balance_adding_htlc(htlc, LOCAL),
			     balance_adding_htlc(htlc, REMOTE));
		channel->view[sidechanged].owed_msat[LOCAL]
			+= balance_adding_htlc(htlc, LOCAL);
		channel->view[sidechanged].owed_msat[REMOTE]
			+= balance_adding_htlc(htlc, REMOTE);
	} else if ((preflags & committed_f) && !(postflags & committed_f)) {
		status_trace("htlc removed %s: local %+"PRIi64" remote %+"PRIi64,
			     side_to_str(sidechanged),
			     balance_removing_htlc(htlc, LOCAL),
			     balance_removing_htlc(htlc, REMOTE));
		channel->view[sidechanged].owed_msat[LOCAL]
			+= balance_removing_htlc(htlc, LOCAL);
		channel->view[sidechanged].owed_msat[REMOTE]
			+= balance_removing_htlc(htlc, REMOTE);
	}
}

static void append_htlc(const struct htlc ***htlcs, const struct htlc *h)
{
	size_t n;

	if (!htlcs)
		return;

	n = tal_count(*htlcs);
	tal_resize(htlcs, n+1);
	(*htlcs)[n] = h;
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
	size_t i;

	for (h = htlc_map_first(channel->htlcs, &it);
	     h;
	     h = htlc_map_next(channel->htlcs, &it)) {
		for (i = 0; i < n_hstates; i++) {
			if (h->state == htlc_states[i]) {
				htlc_incstate(channel, h, sidechanged);
				dump_htlc(h, prefix);
				append_htlc(htlcs, h);
				cflags |= (htlc_state_flags(htlc_states[i])
					   ^ htlc_state_flags(h->state));
			}
		}
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
 *      - SHOULD fail the channel,
 */
u32 approx_max_feerate(const struct channel *channel)
{
	size_t num;
	u64 weight;
	const struct htlc **committed, **adding, **removing;

	gather_htlcs(tmpctx, channel, !channel->funder,
		     &committed, &removing, &adding);

	/* Assume none are trimmed; this gives lower bound on feerate. */
	num = tal_count(committed) + tal_count(adding) - tal_count(removing);

	weight = 724 + 172 * num;

	return channel->view[!channel->funder].owed_msat[channel->funder]
		/ weight * 1000;
}

bool can_funder_afford_feerate(const struct channel *channel, u32 feerate_per_kw)
{
	u64 fee_msat, dust = dust_limit_satoshis(channel, !channel->funder);
	size_t untrimmed;
	const struct htlc **committed, **adding, **removing;
	gather_htlcs(tmpctx, channel, !channel->funder,
		     &committed, &removing, &adding);

	untrimmed = commit_tx_num_untrimmed(committed, feerate_per_kw, dust,
					    !channel->funder)
			+ commit_tx_num_untrimmed(adding, feerate_per_kw, dust,
						  !channel->funder)
			- commit_tx_num_untrimmed(removing, feerate_per_kw, dust,
						  !channel->funder);

	fee_msat = commit_tx_base_fee(feerate_per_kw, untrimmed);

	/* BOLT #2:
	 *
	 *   - if the sender cannot afford the new fee rate on the receiving
	 *     node's current commitment transaction:
	 *     - SHOULD fail the channel
	 */
	/* Note: sender == funder */

	/* How much does it think it has?  Must be >= reserve + fee */
	return channel->view[!channel->funder].owed_msat[channel->funder]
		>= channel_reserve_msat(channel, channel->funder) + fee_msat;
}

bool channel_update_feerate(struct channel *channel, u32 feerate_per_kw)
{
	if (!can_funder_afford_feerate(channel, feerate_per_kw))
		return false;

	status_trace("Setting %s feerate to %u",
		     side_to_str(!channel->funder), feerate_per_kw);

	channel->view[!channel->funder].feerate_per_kw = feerate_per_kw;
	channel->changes_pending[!channel->funder] = true;
	return true;
}

u32 channel_feerate(const struct channel *channel, enum side side)
{
	return channel->view[side].feerate_per_kw;
}

bool channel_sending_commit(struct channel *channel,
			    const struct htlc ***htlcs)
{
	const enum htlc_state states[] = { SENT_ADD_HTLC,
					   SENT_REMOVE_REVOCATION,
					   SENT_ADD_REVOCATION,
					   SENT_REMOVE_HTLC };
	status_trace("Trying commit");

	if (!channel->changes_pending[REMOTE]) {
		assert(change_htlcs(channel, REMOTE, states, ARRAY_SIZE(states),
				    htlcs, "testing sending_commit") == 0);
		return false;
	}

	change_htlcs(channel, REMOTE, states, ARRAY_SIZE(states),
		     htlcs, "sending_commit");
	channel->changes_pending[REMOTE] = false;

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

	status_trace("Received revoke_and_ack");
	change = change_htlcs(channel, LOCAL, states, ARRAY_SIZE(states),
			      htlcs, "rcvd_revoke_and_ack");

	/* Their ack can queue changes on our side. */
	if (change & HTLC_LOCAL_F_PENDING)
		channel->changes_pending[LOCAL] = true;

	/* For funder, ack also means time to apply new feerate locally. */
	if (channel->funder == LOCAL &&
	    (channel->view[LOCAL].feerate_per_kw
	     != channel->view[REMOTE].feerate_per_kw)) {
		status_trace("Applying feerate %u to LOCAL",
			     channel->view[REMOTE].feerate_per_kw);
		channel->view[LOCAL].feerate_per_kw
			= channel->view[REMOTE].feerate_per_kw;
		channel->changes_pending[LOCAL] = true;
	}

	return channel->changes_pending[LOCAL];
}

/* FIXME: We can actually merge these two... */
bool channel_rcvd_commit(struct channel *channel, const struct htlc ***htlcs)
{
	const enum htlc_state states[] = { RCVD_ADD_REVOCATION,
					   RCVD_REMOVE_HTLC,
					   RCVD_ADD_HTLC,
					   RCVD_REMOVE_REVOCATION };

	status_trace("Received commit");
	if (!channel->changes_pending[LOCAL]) {
		assert(change_htlcs(channel, LOCAL, states, ARRAY_SIZE(states),
				    htlcs, "testing rcvd_commit") == 0);
		return false;
	}

	change_htlcs(channel, LOCAL, states, ARRAY_SIZE(states), htlcs,
		     "rcvd_commit");

	channel->changes_pending[LOCAL] = false;
	return true;
}

bool channel_sending_revoke_and_ack(struct channel *channel)
{
	int change;
	const enum htlc_state states[] = { RCVD_ADD_ACK_COMMIT,
					   RCVD_REMOVE_COMMIT,
					   RCVD_ADD_COMMIT,
					   RCVD_REMOVE_ACK_COMMIT };
	status_trace("Sending revoke_and_ack");
	change = change_htlcs(channel, REMOTE, states, ARRAY_SIZE(states), NULL,
			      "sending_revoke_and_ack");

	/* Our ack can queue changes on their side. */
	if (change & HTLC_REMOTE_F_PENDING)
		channel->changes_pending[REMOTE] = true;

	/* For non-funder, sending ack means we apply any fund changes to them */
	if (channel->funder == REMOTE
	    && (channel->view[LOCAL].feerate_per_kw
		!= channel->view[REMOTE].feerate_per_kw)) {
		status_trace("Applying feerate %u to REMOTE",
			     channel->view[LOCAL].feerate_per_kw);
		channel->view[REMOTE].feerate_per_kw
			= channel->view[LOCAL].feerate_per_kw;
		channel->changes_pending[REMOTE] = true;
	}

	return channel->changes_pending[REMOTE];
}

size_t num_channel_htlcs(const struct channel *channel)
{
	struct htlc_map_iter it;
	const struct htlc *htlc;
	size_t n = 0;

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		/* FIXME: Clean these out! */
		if (!htlc_is_dead(htlc))
			n++;
	}
	return n;
}

static bool adjust_balance(struct channel *channel, struct htlc *htlc)
{
	enum side side;

	for (side = 0; side < NUM_SIDES; side++) {
		/* Did it ever add it? */
		if (!htlc_has(htlc, HTLC_FLAG(side, HTLC_F_WAS_COMMITTED)))
			continue;

		/* Add it. */
		channel->view[side].owed_msat[LOCAL]
			+= balance_adding_htlc(htlc, LOCAL);
		channel->view[side].owed_msat[REMOTE]
			+= balance_adding_htlc(htlc, REMOTE);

		/* If it is no longer committed, remove it (depending
		 * on fail || fulfill). */
		if (htlc_has(htlc, HTLC_FLAG(side, HTLC_F_COMMITTED)))
			continue;

		if (!htlc->fail && !htlc->failcode && !htlc->r) {
			status_trace("%s HTLC %"PRIu64
				     " %s neither fail nor fulfill?",
				     htlc_state_owner(htlc->state) == LOCAL
				     ? "out" : "in",
				     htlc->id,
				     htlc_state_name(htlc->state));
			return false;
		}
		channel->view[side].owed_msat[LOCAL]
			+= balance_removing_htlc(htlc, LOCAL);
		channel->view[side].owed_msat[REMOTE]
			+= balance_removing_htlc(htlc, REMOTE);
	}
	return true;
}

bool channel_force_htlcs(struct channel *channel,
			 const struct added_htlc *htlcs,
			 const enum htlc_state *hstates,
			 const struct fulfilled_htlc *fulfilled,
			 const enum side *fulfilled_sides,
			 const struct failed_htlc **failed,
			 const enum side *failed_sides)
{
	size_t i;

	if (tal_count(hstates) != tal_count(htlcs)) {
		status_trace("#hstates %zu != #htlcs %zu",
			     tal_count(hstates), tal_count(htlcs));
		return false;
	}

	if (tal_count(fulfilled) != tal_count(fulfilled_sides)) {
		status_trace("#fulfilled sides %zu != #fulfilled %zu",
			     tal_count(fulfilled_sides), tal_count(fulfilled));
		return false;
	}

	if (tal_count(failed) != tal_count(failed_sides)) {
		status_trace("#failed sides %zu != #failed %zu",
			     tal_count(failed_sides), tal_count(failed));
		return false;
	}
	for (i = 0; i < tal_count(htlcs); i++) {
		enum channel_add_err e;
		struct htlc *htlc;

		status_trace("Restoring HTLC %zu/%zu:"
			     " id=%"PRIu64" msat=%"PRIu64" cltv=%u"
			     " payment_hash=%s",
			     i, tal_count(htlcs),
			     htlcs[i].id, htlcs[i].amount_msat,
			     htlcs[i].cltv_expiry,
			     type_to_string(tmpctx, struct sha256,
					    &htlcs[i].payment_hash));

		e = add_htlc(channel, hstates[i],
			     htlcs[i].id, htlcs[i].amount_msat,
			     htlcs[i].cltv_expiry,
			     &htlcs[i].payment_hash,
			     htlcs[i].onion_routing_packet, &htlc, false);
		if (e != CHANNEL_ERR_ADD_OK) {
			status_trace("%s HTLC %"PRIu64" failed error %u",
				     htlc_state_owner(hstates[i]) == LOCAL
				     ? "out" : "in", htlcs[i].id, e);
			return false;
		}
	}

	for (i = 0; i < tal_count(fulfilled); i++) {
		struct htlc *htlc = channel_get_htlc(channel,
						     fulfilled_sides[i],
						     fulfilled[i].id);
		if (!htlc) {
			status_trace("Fulfill %s HTLC %"PRIu64" not found",
				     fulfilled_sides[i] == LOCAL ? "out" : "in",
				     fulfilled[i].id);
			return false;
		}
		if (htlc->r) {
			status_trace("Fulfill %s HTLC %"PRIu64" already fulfilled",
				     fulfilled_sides[i] == LOCAL ? "out" : "in",
				     fulfilled[i].id);
			return false;
		}
		if (htlc->fail) {
			status_trace("Fulfill %s HTLC %"PRIu64" already failed",
				     fulfilled_sides[i] == LOCAL ? "out" : "in",
				     fulfilled[i].id);
			return false;
		}
		if (htlc->failcode) {
			status_trace("Fulfill %s HTLC %"PRIu64" already fail %u",
				     fulfilled_sides[i] == LOCAL ? "out" : "in",
				     fulfilled[i].id, htlc->failcode);
			return false;
		}
		if (!htlc_has(htlc, HTLC_REMOVING)) {
			status_trace("Fulfill %s HTLC %"PRIu64" state %s",
				     fulfilled_sides[i] == LOCAL ? "out" : "in",
				     fulfilled[i].id,
				     htlc_state_name(htlc->state));
			return false;
		}
		htlc->r = tal_dup(htlc, struct preimage,
				  &fulfilled[i].payment_preimage);
	}

	for (i = 0; i < tal_count(failed); i++) {
		struct htlc *htlc;
		htlc = channel_get_htlc(channel, failed_sides[i],
					failed[i]->id);
		if (!htlc) {
			status_trace("Fail %s HTLC %"PRIu64" not found",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     failed[i]->id);
			return false;
		}
		if (htlc->r) {
			status_trace("Fail %s HTLC %"PRIu64" already fulfilled",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     failed[i]->id);
			return false;
		}
		if (htlc->fail) {
			status_trace("Fail %s HTLC %"PRIu64" already failed",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     failed[i]->id);
			return false;
		}
		if (htlc->failcode) {
			status_trace("Fail %s HTLC %"PRIu64" already fail %u",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     failed[i]->id, htlc->failcode);
			return false;
		}
		if (!htlc_has(htlc, HTLC_REMOVING)) {
			status_trace("Fail %s HTLC %"PRIu64" state %s",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     fulfilled[i].id,
				     htlc_state_name(htlc->state));
			return false;
		}
		htlc->failcode = failed[i]->failcode;
		if (failed[i]->failreason)
			htlc->fail = tal_dup_arr(htlc, u8,
						 failed[i]->failreason,
						 tal_count(failed[i]->failreason),
						 0);
		else
			htlc->fail = NULL;
		if (failed[i]->scid)
			htlc->failed_scid = tal_dup(htlc,
						    struct short_channel_id,
						    failed[i]->scid);
		else
			htlc->failed_scid = NULL;
	}

	for (i = 0; i < tal_count(htlcs); i++) {
		struct htlc *htlc;
		htlc = channel_get_htlc(channel,
					htlc_state_owner(hstates[i]),
					htlcs[i].id);

		if (!adjust_balance(channel, htlc))
			return false;
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
