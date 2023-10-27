#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/blockheight_states.h>
#include <common/channel_type.h>
#include <common/fee_states.h>
#include <common/initial_channel.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/type_to_string.h>

struct channel *new_initial_channel(const tal_t *ctx,
				    const struct channel_id *cid,
				    const struct bitcoin_outpoint *funding,
				    u32 minimum_depth,
				    const struct height_states *height_states TAKES,
				    u32 lease_expiry,
				    struct amount_sat funding_sats,
				    struct amount_msat local_msatoshi,
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
	struct channel *channel = tal(ctx, struct channel);
	struct amount_msat remote_msatoshi;

	channel->cid = *cid;
	channel->funding = *funding;
	channel->funding_sats = funding_sats;
	channel->minimum_depth = minimum_depth;
	channel->lease_expiry = lease_expiry;
	if (!amount_sat_sub_msat(&remote_msatoshi,
				 channel->funding_sats, local_msatoshi))
		return tal_free(channel);

	channel->opener = opener;
	channel->config[LOCAL] = *local;
	channel->config[REMOTE] = *remote;
	channel->funding_pubkey[LOCAL] = *local_funding_pubkey;
	channel->funding_pubkey[REMOTE] = *remote_funding_pubkey;
	channel->htlcs = NULL;

	/* takes() if necessary */
	channel->fee_states = dup_fee_states(channel, fee_states);

	/* takes() if necessary */
	if (!height_states)
		channel->blockheight_states = NULL;
	else
		channel->blockheight_states
			= dup_height_states(channel, height_states);

	channel->view[LOCAL].owed[LOCAL]
		= channel->view[REMOTE].owed[LOCAL]
		= local_msatoshi;
	channel->view[REMOTE].owed[REMOTE]
		= channel->view[LOCAL].owed[REMOTE]
		= remote_msatoshi;

	channel->view[LOCAL].lowest_splice_amnt[LOCAL] = 0;
	channel->view[LOCAL].lowest_splice_amnt[REMOTE] = 0;
	channel->view[REMOTE].lowest_splice_amnt[LOCAL] = 0;
	channel->view[REMOTE].lowest_splice_amnt[REMOTE] = 0;

	channel->basepoints[LOCAL] = *local_basepoints;
	channel->basepoints[REMOTE] = *remote_basepoints;

	channel->commitment_number_obscurer
		= commit_number_obscurer(&channel->basepoints[opener].payment,
					 &channel->basepoints[!opener].payment);

	channel->option_wumbo = option_wumbo;
	/* takes() if necessary */
	channel->type = tal_dup(channel, struct channel_type, type);

	return channel;
}

/* FIXME: We could cache this. */
struct bitcoin_tx *initial_channel_tx(const tal_t *ctx,
				      const u8 **wscript,
				      const struct channel *channel,
				      const struct pubkey *per_commitment_point,
				      enum side side,
				      struct wally_tx_output *direct_outputs[NUM_SIDES],
				      char** err_reason)
{
	struct keyset keyset;
	struct bitcoin_tx *init_tx;
	u32 csv_lock;

	/* This assumes no HTLCs! */
	assert(!channel->htlcs);

	if (!derive_keyset(per_commitment_point,
			   &channel->basepoints[side],
			   &channel->basepoints[!side],
			   channel_has(channel, OPT_STATIC_REMOTEKEY),
			   &keyset)) {
		*err_reason = "Cannot derive keyset";
		return NULL;
	}

	/* Figure out the csv_lock (if there's a lease) */
	if (channel->lease_expiry == 0)
		csv_lock = 1;
	else
		/* For the initial commitment, starts max lease */
		csv_lock = channel->lease_expiry
			- get_blockheight(channel->blockheight_states,
					  channel->opener,
					  side);

	init_tx = initial_commit_tx(ctx, &channel->funding,
				    channel->funding_sats,
				    channel->funding_pubkey,
				    channel->opener,
				    /* They specify our to_self_delay and v.v. */
				    channel->config[!side].to_self_delay,
				    &keyset,
				    channel_feerate(channel, side),
				    channel->config[side].dust_limit,
				    channel->view[side].owed[side],
				    channel->view[side].owed[!side],
				    channel->config[!side].channel_reserve,
				    0 ^ channel->commitment_number_obscurer,
				    direct_outputs,
				    side, csv_lock,
				    channel_has(channel, OPT_ANCHOR_OUTPUTS),
				    channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX),
				    err_reason);

	if (init_tx) {
		psbt_input_add_pubkey(init_tx->psbt, 0,
				      &channel->funding_pubkey[side], false /* is_taproot */);
		psbt_input_add_pubkey(init_tx->psbt, 0,
				      &channel->funding_pubkey[!side], false /* is_taproot */);
	}

	if (wscript) {
		*wscript = bitcoin_redeem_2of2(ctx,
					       &channel->funding_pubkey[side],
					       &channel->funding_pubkey[!side]);
	}

	return init_tx;
}

const char *channel_update_funding(struct channel *channel,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   s64 splice_amnt)
{
	s64 funding_diff = (s64)funding_sats.satoshis - (s64)channel->funding_sats.satoshis; /* Raw: splicing */
	s64 remote_splice_amnt = funding_diff - splice_amnt;

	channel->funding = *funding;
	channel->funding_sats = funding_sats;

	if (splice_amnt * 1000 + channel->view[LOCAL].owed[LOCAL].millisatoshis < 0) /* Raw: splicing */
		return tal_fmt(tmpctx, "Channel funding update would make local"
			       " balance negative.");

	channel->view[LOCAL].owed[LOCAL].millisatoshis += splice_amnt * 1000; /* Raw: splicing */
	channel->view[REMOTE].owed[LOCAL].millisatoshis += splice_amnt * 1000; /* Raw: splicing */

	if (remote_splice_amnt * 1000 + channel->view[LOCAL].owed[REMOTE].millisatoshis < 0) /* Raw: splicing */
		return tal_fmt(tmpctx, "Channel funding update would make"
			       " remote balance negative.");

	channel->view[LOCAL].owed[REMOTE].millisatoshis += remote_splice_amnt * 1000; /* Raw: splicing */
	channel->view[REMOTE].owed[REMOTE].millisatoshis += remote_splice_amnt * 1000; /* Raw: splicing */

	return NULL;
}

u32 channel_feerate(const struct channel *channel, enum side side)
{
	return get_feerate(channel->fee_states, channel->opener, side);
}

u32 channel_blockheight(const struct channel *channel, enum side side)
{
	return get_blockheight(channel->blockheight_states,
			       channel->opener, side);
}

struct channel_type *channel_upgradable_type(const tal_t *ctx,
					     const struct channel *channel)
{
	if (!channel_has(channel, OPT_STATIC_REMOTEKEY))
		return channel_type_static_remotekey(ctx);

	return NULL;
}

struct channel_type *channel_desired_type(const tal_t *ctx,
					  const struct channel *channel)
{
	/* We don't actually want to downgrade anchors! */
	if (channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX))
		return channel_type_anchors_zero_fee_htlc(ctx);

	/* We don't actually want to downgrade anchors! */
	if (channel_has(channel, OPT_ANCHOR_OUTPUTS))
		return channel_type_anchor_outputs(ctx);

	/* For now, we just want option_static_remotekey */
	return channel_type_static_remotekey(ctx);
}

bool channel_has(const struct channel *channel, int feature)
{
	return channel_type_has(channel->type, feature);
}

bool channel_has_anchors(const struct channel *channel)
{
	return channel_type_has_anchors(channel->type);
}

static char *fmt_channel_view(const tal_t *ctx, const struct channel_view *view)
{
	return tal_fmt(ctx, "{ owed_local=%s,"
		       " owed_remote=%s }",
		       type_to_string(tmpctx, struct amount_msat,
				      &view->owed[LOCAL]),
		       type_to_string(tmpctx, struct amount_msat,
				      &view->owed[REMOTE]));
}

/* FIXME: This should reference HTLCs somehow, and feerates! */
static char *fmt_channel(const tal_t *ctx, const struct channel *channel)
{
	return tal_fmt(ctx, "{ funding=%s,"
		       " opener=%s,"
		       " local=%s,"
		       " remote=%s }",
		       type_to_string(tmpctx, struct amount_sat,
				      &channel->funding_sats),
		       side_to_str(channel->opener),
		       fmt_channel_view(ctx, &channel->view[LOCAL]),
		       fmt_channel_view(ctx, &channel->view[REMOTE]));
}
/* Magic comment. */
REGISTER_TYPE_TO_STRING(channel, fmt_channel);
