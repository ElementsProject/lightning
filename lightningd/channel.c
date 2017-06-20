#include "channel.h"
#include "commit_tx.h"
#include "type_to_string.h"
#include <assert.h>
#include <bitcoin/preimage.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <daemon/htlc.h>
#include <inttypes.h>
#include <lightningd/channel_config.h>
#include <lightningd/htlc_tx.h>
#include <lightningd/htlc_wire.h>
#include <lightningd/key_derive.h>
#include <lightningd/status.h>
#include <string.h>

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
		     htlc->malformed ? "MALFORMED" : "");
}

void dump_htlcs(const struct channel *channel, const char *prefix)
{
	struct htlc_map_iter it;
	const struct htlc *htlc;

	for (htlc = htlc_map_first(&channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(&channel->htlcs, &it)) {
		dump_htlc(htlc, prefix);
	}
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

	for (htlc = htlc_map_first(&channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(&channel->htlcs, &it)) {
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

static void destroy_htlc_map(struct channel *channel)
{
	htlc_map_clear(&channel->htlcs);
}

struct channel *new_channel(const tal_t *ctx,
			    const struct sha256_double *funding_txid,
			    unsigned int funding_txout,
			    u64 funding_satoshis,
			    u64 local_msatoshi,
			    u32 feerate_per_kw,
			    const struct channel_config *local,
			    const struct channel_config *remote,
			    const struct basepoints *local_basepoints,
			    const struct basepoints *remote_basepoints,
			    const struct pubkey *local_funding_pubkey,
			    const struct pubkey *remote_funding_pubkey,
			    enum side funder)
{
	struct channel *channel = tal(ctx, struct channel);

	channel->funding_txid = *funding_txid;
	channel->funding_txout = funding_txout;
	if (funding_satoshis > UINT64_MAX / 1000)
		return tal_free(channel);

	channel->funding_msat = funding_satoshis * 1000;
	if (local_msatoshi > channel->funding_msat)
		return tal_free(channel);

	channel->funder = funder;
	channel->config[LOCAL] = local;
	channel->config[REMOTE] = remote;
	channel->funding_pubkey[LOCAL] = *local_funding_pubkey;
	channel->funding_pubkey[REMOTE] = *remote_funding_pubkey;
	htlc_map_init(&channel->htlcs);

	channel->view[LOCAL].feerate_per_kw
		= channel->view[REMOTE].feerate_per_kw
		= feerate_per_kw;

	channel->view[LOCAL].owed_msat[LOCAL]
		= channel->view[REMOTE].owed_msat[LOCAL]
		= local_msatoshi;
	channel->view[REMOTE].owed_msat[REMOTE]
		= channel->view[LOCAL].owed_msat[REMOTE]
		= channel->funding_msat - local_msatoshi;

	channel->basepoints[LOCAL] = *local_basepoints;
	channel->basepoints[REMOTE] = *remote_basepoints;

	channel->commitment_number_obscurer
		= commit_number_obscurer(&channel->basepoints[funder].payment,
					 &channel->basepoints[!funder].payment);

	tal_add_destructor(channel, destroy_htlc_map);
	return channel;
}

static void add_htlcs(struct bitcoin_tx ***txs,
		      const u8 ***wscripts,
		      const struct htlc **htlcmap,
		      const struct channel *channel,
		      const struct pubkey *side_payment_key,
		      const struct pubkey *other_payment_key,
		      const struct pubkey *side_revocation_key,
		      const struct pubkey *side_delayed_payment_key,
		      enum side side)
{
	size_t i, n;
	struct sha256_double txid;
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
					     htlc,
					     to_self_delay(channel, side),
					     side_revocation_key,
					     side_delayed_payment_key,
					     feerate_per_kw);
			wscript	= bitcoin_wscript_htlc_offer(*wscripts,
							     side_payment_key,
							     other_payment_key,
							     &htlc->rhash,
							     side_revocation_key);
		} else {
			tx = htlc_success_tx(*txs, &txid, i,
					     htlc,
					     to_self_delay(channel, side),
					     side_revocation_key,
					     side_delayed_payment_key,
					     feerate_per_kw);
			wscript	= bitcoin_wscript_htlc_receive(*wscripts,
							       &htlc->expiry,
							       side_payment_key,
							       other_payment_key,
							       &htlc->rhash,
							       side_revocation_key);
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
	/* Payment keys for @side and !@side */
	struct pubkey side_payment_key, other_payment_key;
	/* Delayed payment key for @side */
	struct pubkey side_delayed_payment_key;
	/* Revocation payment key for @side */
	struct pubkey side_revocation_key;

	if (!derive_simple_key(&channel->basepoints[side].payment,
			       per_commitment_point,
			       &side_payment_key))
		return NULL;

	if (!derive_simple_key(&channel->basepoints[!side].payment,
			       per_commitment_point,
			       &other_payment_key))
		return NULL;

	if (!derive_simple_key(&channel->basepoints[side].delayed_payment,
			       per_commitment_point,
			       &side_delayed_payment_key))
		return NULL;

	if (!derive_revocation_key(&channel->basepoints[!side].revocation,
				   per_commitment_point,
				   &side_revocation_key))
		return NULL;

	/* Figure out what @side will already be committed to. */
	gather_htlcs(ctx, channel, side, &committed, NULL, NULL);

	/* NULL map only allowed at beginning, when we know no HTLCs */
	if (!htlcmap)
		assert(tal_count(committed) == 0);

	txs = tal_arr(ctx, struct bitcoin_tx *, 1);
	txs[0] = commit_tx(ctx, &channel->funding_txid,
		       channel->funding_txout,
		       channel->funding_msat / 1000,
		       channel->funder,
		       to_self_delay(channel, side),
		       &side_revocation_key,
		       &side_delayed_payment_key,
		       &side_payment_key,
		       &other_payment_key,
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

	if (htlcmap)
		add_htlcs(&txs, wscripts, *htlcmap, channel,
			  &side_payment_key, &other_payment_key,
			  &side_revocation_key, &side_delayed_payment_key,
			  side);

	tal_free(committed);
	return txs;
}

struct channel *copy_channel(const tal_t *ctx, const struct channel *old)
{
	struct channel *new = tal_dup(ctx, struct channel, old);
	htlc_map_copy(&new->htlcs, &old->htlcs);
	return new;
}

static enum channel_add_err add_htlc(struct channel *channel,
				     enum side sender,
				     u64 id, u64 msatoshi, u32 cltv_expiry,
				     const struct sha256 *payment_hash,
				     const u8 routing[TOTAL_PACKET_SIZE],
				     struct htlc **htlcp,
				     bool enforce_aggregate_limits)
{
	const tal_t *tmpctx = tal_tmpctx(channel);
	struct htlc *htlc, *old;
	s64 msat_in_htlcs, fee_msat, balance_msat;
	enum side recipient = !sender;
	const struct htlc **committed, **adding, **removing;
	enum channel_add_err e;
	const struct channel_view *view;
	size_t i;

	htlc = tal(tmpctx, struct htlc);

	/* FIXME: Don't need fields: peer, deadline, src. */

	if (sender == LOCAL)
		htlc->state = SENT_ADD_HTLC;
	else
		htlc->state = RCVD_ADD_HTLC;

	htlc->id = id;
	htlc->msatoshi = msatoshi;
	/* FIXME: Change expiry to simple u32 */

	/* BOLT #2:
	 *
	 * A receiving node SHOULD fail the channel if a sending node... sets
	 * `cltv_expiry` to greater or equal to 500000000.
	 */
	if (!blocks_to_abs_locktime(cltv_expiry, &htlc->expiry)) {
		e = CHANNEL_ERR_INVALID_EXPIRY;
		goto out;
	}

	htlc->rhash = *payment_hash;
	htlc->fail = NULL;
	htlc->malformed = 0;
	htlc->r = NULL;
	htlc->routing = tal_dup_arr(htlc, u8, routing, TOTAL_PACKET_SIZE, 0);

	old = htlc_get(&channel->htlcs, htlc->id, htlc_owner(htlc));
	if (old) {
		if (old->state != htlc->state
		    || old->msatoshi != htlc->msatoshi
		    || old->expiry.locktime != htlc->expiry.locktime
		    || !structeq(&old->rhash, &htlc->rhash))
			e = CHANNEL_ERR_DUPLICATE_ID_DIFFERENT;
		else
			e = CHANNEL_ERR_DUPLICATE;
		goto out;
	}

	/* We're always considering the recipient's view of the channel here */
	view = &channel->view[recipient];

	/* BOLT #2:
	 *
	 * A receiving node SHOULD fail the channel if it receives an
	 * `amount_msat` equal to zero, below its own `htlc_minimum_msat`,
	 * or...
	 */
	if (htlc->msatoshi == 0) {
		e = CHANNEL_ERR_HTLC_BELOW_MINIMUM;
		goto out;
	}
	if (htlc->msatoshi < htlc_minimum_msat(channel, recipient)) {
		e = CHANNEL_ERR_HTLC_BELOW_MINIMUM;
		goto out;
	}

	/* BOLT #2:
	 *
	 * For channels with `chain_hash` identifying the Bitcoin blockchain,
	 * the sending node MUST set the 4 most significant bytes of
	 * `amount_msat` to zero.
	 */
	if (htlc->msatoshi & 0xFFFFFFFF00000000ULL) {
		e = CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
		goto out;
	}

	/* Figure out what receiver will already be committed to. */
	gather_htlcs(tmpctx, channel, recipient, &committed, &removing, &adding);
	htlc_arr_append(&adding, htlc);

	/* BOLT #2:
	 *
	 * A receiving node SHOULD fail the channel if a sending node
	 * adds more than its `max_accepted_htlcs` HTLCs to its local
	 * commitment transaction */
	if (enforce_aggregate_limits
	    && tal_count(committed) - tal_count(removing) + tal_count(adding)
	    > max_accepted_htlcs(channel, recipient)) {
		e = CHANNEL_ERR_TOO_MANY_HTLCS;
		goto out;
	}

	msat_in_htlcs = total_offered_msatoshis(committed, htlc_owner(htlc))
		- total_offered_msatoshis(removing, htlc_owner(htlc))
		+ total_offered_msatoshis(adding, htlc_owner(htlc));

	/* BOLT #2:
	 *
	 * A receiving node SHOULD fail the channel if a sending node ... or
	 * adds more than its `max_htlc_value_in_flight_msat` worth of offered
	 * HTLCs to its local commitment transaction */
	if (enforce_aggregate_limits
	    && msat_in_htlcs > max_htlc_value_in_flight_msat(channel, recipient)) {
		e = CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
		goto out;
	}

	/* BOLT #2:
	 *
	 * or which the sending node cannot afford at the current
	 * `feerate_per_kw` while maintaining its channel reserve.
	 */
	if (channel->funder == htlc_owner(htlc)) {
		u64 feerate = view->feerate_per_kw;
		u64 dust = dust_limit_satoshis(channel, recipient);
		size_t untrimmed;

		assert(feerate >= 1);
		assert(dust >= 1);
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
		e = CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;
		goto out;
	}

	dump_htlc(htlc, "NEW:");
	htlc_map_add(&channel->htlcs, tal_steal(channel, htlc));
	e = CHANNEL_ERR_ADD_OK;
	if (htlcp)
		*htlcp = htlc;

out:
	tal_free(tmpctx);
	return e;
}

enum channel_add_err channel_add_htlc(struct channel *channel,
				      enum side sender,
				      u64 id,
				      u64 msatoshi,
				      u32 cltv_expiry,
				      const struct sha256 *payment_hash,
				      const u8 routing[TOTAL_PACKET_SIZE])
{
	/* FIXME: check expiry etc. against config. */
	return add_htlc(channel, sender, id, msatoshi, cltv_expiry, payment_hash,
			routing, NULL, true);
}

struct htlc *channel_get_htlc(struct channel *channel, enum side sender, u64 id)
{
	return htlc_get(&channel->htlcs, id, sender);
}

enum channel_remove_err channel_fulfill_htlc(struct channel *channel,
					      enum side owner,
					      u64 id,
					      const struct preimage *preimage)
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
	 * A receiving node MUST check that the `payment_preimage` value in
	 * `update_fulfill_htlc` SHA256 hashes to the corresponding HTLC
	 * `payment_hash`, and MUST fail the channel if it does not.
	 */
	if (!structeq(&hash, &htlc->rhash))
		return CHANNEL_ERR_BAD_PREIMAGE;

	htlc->r = tal_dup(htlc, struct preimage, preimage);

	/* BOLT #2:
	 *
	 * A receiving node MUST check that `id` corresponds to an HTLC in its
	 * current commitment transaction, and MUST fail the channel if it
	 * does not.
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
	 * A node MUST NOT send `update_fulfill_htlc` until an HTLC is
	 * irrevocably committed in both sides' commitment transactions.
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
	dump_htlc(htlc, "FULFILL:");

	return CHANNEL_ERR_REMOVE_OK;
}

enum channel_remove_err channel_fail_htlc(struct channel *channel,
					  enum side owner, u64 id)
{
	struct htlc *htlc;

	htlc = channel_get_htlc(channel, owner, id);
	if (!htlc)
		return CHANNEL_ERR_NO_SUCH_ID;

	/* BOLT #2:
	 *
	 * A receiving node MUST check that `id` corresponds to an HTLC in its
	 * current commitment transaction, and MUST fail the channel if it
	 * does not.
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
	dump_htlc(htlc, "FAIL:");

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

	for (h = htlc_map_first(&channel->htlcs, &it);
	     h;
	     h = htlc_map_next(&channel->htlcs, &it)) {
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

/* FIXME: Handle fee changes too. */
bool channel_sending_commit(struct channel *channel,
			    const struct htlc ***htlcs)
{
	int change;
	const enum htlc_state states[] = { SENT_ADD_HTLC,
					   SENT_REMOVE_REVOCATION,
					   SENT_ADD_REVOCATION,
					   SENT_REMOVE_HTLC };
	status_trace("Trying commit");
	change = change_htlcs(channel, REMOTE, states, ARRAY_SIZE(states),
			      htlcs, "sending_commit");
	return change & HTLC_REMOTE_F_COMMITTED;
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
	return change & HTLC_LOCAL_F_COMMITTED;
}

/* FIXME: We can actually merge these two... */
bool channel_rcvd_commit(struct channel *channel, const struct htlc ***htlcs)
{
	int change;
	const enum htlc_state states[] = { RCVD_ADD_REVOCATION,
					   RCVD_REMOVE_HTLC,
					   RCVD_ADD_HTLC,
					   RCVD_REMOVE_REVOCATION };

	status_trace("Received commit");
	change = change_htlcs(channel, LOCAL, states, ARRAY_SIZE(states), htlcs,
			      "rcvd_commit");
	return change & HTLC_LOCAL_F_COMMITTED;
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
	return change & HTLC_REMOTE_F_PENDING;
}

/* FIXME: Trivial to optimize: set flag on channel_sending_commit,
 * clear in channel_rcvd_revoke_and_ack. */
bool channel_awaiting_revoke_and_ack(const struct channel *channel)
{
	const enum htlc_state states[] = { SENT_ADD_COMMIT,
					   SENT_REMOVE_ACK_COMMIT,
					   SENT_ADD_ACK_COMMIT,
					   SENT_REMOVE_COMMIT };
	struct htlc_map_iter it;
	struct htlc *h;
	size_t i;

	for (h = htlc_map_first(&channel->htlcs, &it);
	     h;
	     h = htlc_map_next(&channel->htlcs, &it)) {
		for (i = 0; i < ARRAY_SIZE(states); i++)
			if (h->state == states[i])
				return true;
	}
	return false;
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

		if (!htlc->fail && !htlc->malformed && !htlc->r) {
			status_trace("%s HTLC %"PRIu64
				     " %s neither fail nor fulfull?",
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
			 const struct failed_htlc *failed,
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
			     " id=%"PRIu64" msat=%"PRIu64" ctlv=%u"
			     " payment_hash=%s",
			     i, tal_count(htlcs),
			     htlcs[i].id, htlcs[i].amount_msat,
			     htlcs[i].cltv_expiry,
			     type_to_string(trc, struct sha256,
					    &htlcs[i].payment_hash));

		e = add_htlc(channel, htlc_state_owner(hstates[i]),
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

		/* Override state. */
		htlc->state = hstates[i];
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
					failed[i].id);
		if (!htlc) {
			status_trace("Fail %s HTLC %"PRIu64" not found",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     failed[i].id);
			return false;
		}
		if (htlc->r) {
			status_trace("Fail %s HTLC %"PRIu64" already fulfilled",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     failed[i].id);
			return false;
		}
		if (htlc->fail) {
			status_trace("Fail %s HTLC %"PRIu64" already failed",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     failed[i].id);
			return false;
		}
		if (htlc->malformed) {
			status_trace("Fail %s HTLC %"PRIu64" already malformed",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     failed[i].id);
			return false;
		}
		if (!htlc_has(htlc, HTLC_REMOVING)) {
			status_trace("Fail %s HTLC %"PRIu64" state %s",
				     failed_sides[i] == LOCAL ? "out" : "in",
				     fulfilled[i].id,
				     htlc_state_name(htlc->state));
			return false;
		}
		if (failed[i].malformed)
			htlc->malformed = failed[i].malformed;
		else
			htlc->fail = tal_dup_arr(htlc, u8, failed[i].failreason,
						 tal_len(failed[i].failreason),
						 0);
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

static char *fmt_channel_view(const tal_t *ctx, const struct channel_view *view)
{
	return tal_fmt(ctx, "{ feerate_per_kw=%"PRIu64","
		       " owed_local=%"PRIu64","
		       " owed_remote=%"PRIu64" }",
		       view->feerate_per_kw,
		       view->owed_msat[LOCAL],
		       view->owed_msat[REMOTE]);
}

static char *fmt_channel(const tal_t *ctx, const struct channel *channel)
{
	return tal_fmt(ctx, "{ funding_msat=%"PRIu64","
		       " funder=%s,"
		       " local=%s,"
		       " remote=%s }",
		       channel->funding_msat,
		       side_to_str(channel->funder),
		       fmt_channel_view(ctx, &channel->view[LOCAL]),
		       fmt_channel_view(ctx, &channel->view[REMOTE]));
}
REGISTER_TYPE_TO_STRING(channel, fmt_channel);
