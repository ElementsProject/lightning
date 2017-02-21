#include "channel.h"
#include "commit_tx.h"
#include "type_to_string.h"
#include <assert.h>
#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <daemon/htlc.h>
#include <inttypes.h>
#include <lightningd/channel_config.h>
#include <lightningd/key_derive.h>
#include <status.h>
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
			    u64 push_msat,
			    u32 feerate_per_kw,
			    const struct channel_config *local,
			    const struct channel_config *remote,
			    const struct pubkey *local_revocation_basepoint,
			    const struct pubkey *remote_revocation_basepoint,
			    const struct pubkey *local_payment_basepoint,
			    const struct pubkey *remote_payment_basepoint,
			    const struct pubkey *local_delayed_payment_basepoint,
			    const struct pubkey *remote_delayed_payment_basepoint,
			    enum side funder)
{
	struct channel *channel = tal(ctx, struct channel);

	channel->funding_txid = *funding_txid;
	channel->funding_txout = funding_txout;
	if (funding_satoshis > UINT64_MAX / 1000)
		return tal_free(channel);

	channel->funding_msat = funding_satoshis * 1000;
	if (push_msat > channel->funding_msat)
		return tal_free(channel);

	channel->funder = funder;
	channel->config[LOCAL] = local;
	channel->config[REMOTE] = remote;
	htlc_map_init(&channel->htlcs);

	channel->view[LOCAL].feerate_per_kw
		= channel->view[REMOTE].feerate_per_kw
		= feerate_per_kw;

	channel->view[funder].owed_msat[funder]
		= channel->view[!funder].owed_msat[funder]
		= channel->funding_msat - push_msat;
	channel->view[funder].owed_msat[!funder]
		= channel->view[!funder].owed_msat[!funder]
		= push_msat;

	channel->view[LOCAL].commitment_number
		= channel->view[REMOTE].commitment_number
		= 0;

	channel->revocation_basepoint[LOCAL] = *local_revocation_basepoint;
	channel->revocation_basepoint[REMOTE] = *remote_revocation_basepoint;
	channel->payment_basepoint[LOCAL] = *local_payment_basepoint;
	channel->payment_basepoint[REMOTE] = *remote_payment_basepoint;
	channel->delayed_payment_basepoint[LOCAL]
		= *local_delayed_payment_basepoint;
	channel->delayed_payment_basepoint[REMOTE]
		= *remote_delayed_payment_basepoint;

	channel->commitment_number_obscurer
		= commit_number_obscurer(&channel->payment_basepoint[funder],
					 &channel->payment_basepoint[!funder]);

	tal_add_destructor(channel, destroy_htlc_map);
	return channel;
}

/* FIXME: We could cache this. */
struct bitcoin_tx *channel_tx(const tal_t *ctx,
			      const struct channel *channel,
			      const struct pubkey *per_commitment_point,
			      const struct htlc ***htlcmap,
			      enum side side)
{
	struct bitcoin_tx *tx;
	const struct htlc **committed;
	/* Payment keys for @side and !@side */
	struct pubkey side_payment_key, other_payment_key;
	/* Delayed payment key for @side */
	struct pubkey side_delayed_payment_key;
	/* Revocation payment key for @side */
	struct pubkey side_revocation_key;

	if (!derive_simple_key(&channel->payment_basepoint[side],
			       per_commitment_point,
			       &side_payment_key))
		return NULL;

	if (!derive_simple_key(&channel->payment_basepoint[!side],
			       per_commitment_point,
			       &other_payment_key))
		return NULL;

	if (!derive_simple_key(&channel->delayed_payment_basepoint[side],
			       per_commitment_point,
			       &side_delayed_payment_key))
		return NULL;

	if (!derive_revocation_key(&channel->revocation_basepoint[side],
				   per_commitment_point,
				   &side_revocation_key))
		return NULL;

	/* Figure out what @side will already be committed to. */
	gather_htlcs(ctx, channel, side, &committed, NULL, NULL);

	tx = commit_tx(ctx, &channel->funding_txid,
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
		       channel->view[side].commitment_number
		       ^ channel->commitment_number_obscurer,
		       side);

	tal_free(committed);
	return tx;
}

struct channel *copy_channel(const tal_t *ctx, const struct channel *old)
{
	struct channel *new = tal_dup(ctx, struct channel, old);
	htlc_map_copy(&new->htlcs, &old->htlcs);
	return new;
}

enum channel_add_err channel_add_htlc(struct channel *channel,
				      enum side sender,
				      u64 id,
				      u64 msatoshi,
				      u32 expiry,
				      const struct sha256 *payment_hash,
				      const u8 routing[1254])
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

	if (sender == LOCAL)
		htlc->state = SENT_ADD_HTLC;
	else
		htlc->state = RCVD_ADD_HTLC;
	htlc->id = id;
	htlc->msatoshi = msatoshi;
	if (!blocks_to_abs_locktime(expiry, &htlc->expiry))
		return CHANNEL_ERR_INVALID_EXPIRY;
	htlc->rhash = *payment_hash;
	htlc->r = NULL;

	/* BOLT #2:
	 *
	 * 1. type: 128 (`update_add_htlc`)
	 * 2. data:
	 *    * [8:channel-id]
	 *    * [8:id]
	 *    * [4:amount-msat]
	 *    * [4:cltv-expiry]
	 *    * [32:payment-hash]
	 *    * [1254:onion-routing-packet]
	 */
	htlc->routing = tal_dup_arr(htlc, u8, routing, 1254, 0);

	/* FIXME: check expiry etc. against config. */
	/* FIXME: set deadline */

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
	 * `amount-sat` equal to zero, below its own `htlc-minimum-msat`,
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

	/* Figure out what receiver will already be committed to. */
	gather_htlcs(tmpctx, channel, recipient, &committed, &removing, &adding);
	htlc_arr_append(&adding, htlc);

	/* BOLT #2:
	 *
	 * A receiving node SHOULD fail the channel if a sending node
	 * adds more than its `max-accepted-htlcs` HTLCs to its local
	 * commitment transaction */
	if (tal_count(committed) - tal_count(removing) + tal_count(adding)
	    > max_accepted_htlcs(channel, recipient)) {
		e = CHANNEL_ERR_TOO_MANY_HTLCS;
		goto out;
	}

	msat_in_htlcs = total_offered_msatoshis(committed, htlc_owner(htlc))
		- total_offered_msatoshis(removing, htlc_owner(htlc))
		+ total_offered_msatoshis(adding, htlc_owner(htlc));

	/* BOLT #2:
	 *
	 * A receiving node SHOULD fail the channel if a sending node
	 * adds more than `max-htlc-value-in-flight-msat` in HTLCs to
	 * its local commitment transaction. */
	if (msat_in_htlcs > max_htlc_value_in_flight_msat(channel, recipient)) {
		e = CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
		goto out;
	}

	/* BOLT #2:
	 *
	 * or which the sending node cannot afford at the current `fee-rate`
	 * while maintaining its channel reserve.
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
	assert(balance_msat >= 0);

	/* This is a little subtle:
	 *
	 * The change is being applied to the receiver but it will
	 * come back to the sender after revoke_and_ack.  So the check
	 * here is that the balance to the sender doesn't go below the
	 * sender's reserve. */
	if (balance_msat - fee_msat < (s64)channel_reserve_msat(channel, sender)) {
		e = CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED;
		goto out;
	}

	htlc_map_add(&channel->htlcs, tal_steal(channel, htlc));
	e = CHANNEL_ERR_ADD_OK;

out:
	tal_free(tmpctx);
	return e;
}

struct htlc *channel_get_htlc(struct channel *channel, enum side sender, u64 id)
{
	return htlc_get(&channel->htlcs, id, sender);
}

enum channel_remove_err channel_fulfill_htlc(struct channel *channel,
					      enum side sender,
					      u64 id,
					      const struct preimage *preimage)
{
	struct sha256 hash;
	struct htlc *htlc;

	/* Fulfill is done by !creator of HTLC */
	htlc = channel_get_htlc(channel, !sender, id);
	if (!htlc)
		return CHANNEL_ERR_NO_SUCH_ID;

	if (htlc->r)
		return CHANNEL_ERR_ALREADY_FULFILLED;

	sha256(&hash, preimage, sizeof(*preimage));
	/* BOLT #2:
	 *
	 * A receiving node MUST check that the `payment-preimage` value in
	 * `update-fulfill_htlc` SHA256 hashes to the corresponding HTLC
	 * `payment-hash`, and MUST fail the channel if it does not.
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

/* FIXME: Commit to storage when this happens. */
static bool change_htlcs(struct channel *channel,
			 enum side sidechanged,
			 const enum htlc_state *htlc_states,
			 size_t n_hstates)
{
	struct htlc_map_iter it;
	struct htlc *h;
	bool changed = false;
	size_t i;

	for (h = htlc_map_first(&channel->htlcs, &it);
	     h;
	     h = htlc_map_next(&channel->htlcs, &it)) {
		for (i = 0; i < n_hstates; i++) {
			if (h->state == htlc_states[i]) {
				htlc_incstate(channel, h, sidechanged);
				changed = true;
			}
		}
	}
	return changed;
}

/* FIXME: Handle fee changes too. */
bool channel_sent_commit(struct channel *channel)
{
	const enum htlc_state states[] = { SENT_ADD_HTLC,
					   SENT_REMOVE_REVOCATION,
					   SENT_ADD_REVOCATION,
					   SENT_REMOVE_HTLC };
	status_trace("sent commit");
	return change_htlcs(channel, REMOTE, states, ARRAY_SIZE(states));
}

bool channel_rcvd_revoke_and_ack(struct channel *channel)
{
	const enum htlc_state states[] = { SENT_ADD_COMMIT,
					   SENT_REMOVE_ACK_COMMIT,
					   SENT_ADD_ACK_COMMIT,
					   SENT_REMOVE_COMMIT };

	status_trace("received revoke_and_ack");
	return change_htlcs(channel, LOCAL, states, ARRAY_SIZE(states));
}

/* FIXME: We can actually merge these two... */
bool channel_rcvd_commit(struct channel *channel)
{
	const enum htlc_state states[] = { RCVD_ADD_REVOCATION,
					   RCVD_REMOVE_HTLC,
					   RCVD_ADD_HTLC,
					   RCVD_REMOVE_REVOCATION };

	status_trace("received commit");
	return change_htlcs(channel, LOCAL, states, ARRAY_SIZE(states));
}

bool channel_sent_revoke_and_ack(struct channel *channel)
{
	const enum htlc_state states[] = { RCVD_ADD_ACK_COMMIT,
					   RCVD_REMOVE_COMMIT,
					   RCVD_ADD_COMMIT,
					   RCVD_REMOVE_ACK_COMMIT };
	status_trace("sent revoke_and_ack");
	return change_htlcs(channel, REMOTE, states, ARRAY_SIZE(states));
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
