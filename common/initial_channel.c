#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/features.h>
#include <common/fee_states.h>
#include <common/initial_channel.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/type_to_string.h>
#include <inttypes.h>
#include <wire/peer_wire.h>

struct channel *new_initial_channel(const tal_t *ctx,
				    const struct channel_id *cid,
				    const struct bitcoin_txid *funding_txid,
				    unsigned int funding_txout,
				    u32 minimum_depth,
				    struct amount_sat funding,
				    struct amount_msat local_msatoshi,
				    const struct fee_states *fee_states TAKES,
				    const struct channel_config *local,
				    const struct channel_config *remote,
				    const struct basepoints *local_basepoints,
				    const struct basepoints *remote_basepoints,
				    const struct pubkey *local_funding_pubkey,
				    const struct pubkey *remote_funding_pubkey,
				    bool option_static_remotekey,
				    bool option_anchor_outputs,
				    enum side opener)
{
	struct channel *channel = tal(ctx, struct channel);
	struct amount_msat remote_msatoshi;

	channel->cid = *cid;
	channel->funding_txid = *funding_txid;
	channel->funding_txout = funding_txout;
	channel->funding = funding;
	channel->minimum_depth = minimum_depth;
	if (!amount_sat_sub_msat(&remote_msatoshi,
				 channel->funding, local_msatoshi))
		return tal_free(channel);

	channel->opener = opener;
	channel->config[LOCAL] = *local;
	channel->config[REMOTE] = *remote;
	channel->funding_pubkey[LOCAL] = *local_funding_pubkey;
	channel->funding_pubkey[REMOTE] = *remote_funding_pubkey;
	channel->htlcs = NULL;

	/* takes() if necessary */
	channel->fee_states = dup_fee_states(channel, fee_states);

	channel->view[LOCAL].owed[LOCAL]
		= channel->view[REMOTE].owed[LOCAL]
		= local_msatoshi;
	channel->view[REMOTE].owed[REMOTE]
		= channel->view[LOCAL].owed[REMOTE]
		= remote_msatoshi;

	channel->basepoints[LOCAL] = *local_basepoints;
	channel->basepoints[REMOTE] = *remote_basepoints;

	channel->commitment_number_obscurer
		= commit_number_obscurer(&channel->basepoints[opener].payment,
					 &channel->basepoints[!opener].payment);

	channel->option_static_remotekey = option_static_remotekey;
	channel->option_anchor_outputs = option_anchor_outputs;
	if (option_anchor_outputs)
		assert(option_static_remotekey);
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

	/* This assumes no HTLCs! */
	assert(!channel->htlcs);

	if (!derive_keyset(per_commitment_point,
			   &channel->basepoints[side],
			   &channel->basepoints[!side],
			   channel->option_static_remotekey,
			   &keyset)) {
		*err_reason = "Cannot derive keyset";
		return NULL;
	}

	*wscript = bitcoin_redeem_2of2(ctx,
				       &channel->funding_pubkey[side],
				       &channel->funding_pubkey[!side]);

	init_tx = initial_commit_tx(ctx, &channel->funding_txid,
				    channel->funding_txout,
				    channel->funding,
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
				    side,
				    channel->option_anchor_outputs,
				    err_reason);

	if (init_tx) {
		psbt_input_add_pubkey(init_tx->psbt, 0,
				      &channel->funding_pubkey[side]);
		psbt_input_add_pubkey(init_tx->psbt, 0,
				      &channel->funding_pubkey[!side]);
	}

	return init_tx;
}

u32 channel_feerate(const struct channel *channel, enum side side)
{
	return get_feerate(channel->fee_states, channel->opener, side);
}

#if EXPERIMENTAL_FEATURES
/* BOLT-upgrade_protocol #2:
 * Channel features are explicitly enumerated as `channel_type` bitfields,
 * using odd features bits.  The currently defined types are:
 *   - no features (no bits set)
 *   - `option_static_remotekey` (bit 13)
 *   - `option_anchor_outputs` and `option_static_remotekey` (bits 21 and 13)
 *   - `option_anchors_zero_fee_htlc_tx` and `option_static_remotekey` (bits 23
 *      and 13)
 */
static struct channel_type *new_channel_type(const tal_t *ctx)
{
	struct channel_type *type = tal(ctx, struct channel_type);

	type->features = tal_arr(type, u8, 0);
	return type;
}

static struct channel_type *type_static_remotekey(const tal_t *ctx)
{
	struct channel_type *type = new_channel_type(ctx);

	set_feature_bit(&type->features,
			OPTIONAL_FEATURE(OPT_STATIC_REMOTEKEY));
 	return type;
}

static struct channel_type *type_anchor_outputs(const tal_t *ctx)
{
	struct channel_type *type = new_channel_type(ctx);

	set_feature_bit(&type->features,
			OPTIONAL_FEATURE(OPT_ANCHOR_OUTPUTS));
	set_feature_bit(&type->features,
			OPTIONAL_FEATURE(OPT_STATIC_REMOTEKEY));
	return type;
}

struct channel_type *channel_type(const tal_t *ctx,
				  const struct channel *channel)
{
	if (channel->option_anchor_outputs)
		return type_anchor_outputs(ctx);
	if (channel->option_static_remotekey)
		return type_static_remotekey(ctx);

	return new_channel_type(ctx);
}

struct channel_type **channel_upgradable_types(const tal_t *ctx,
					       const struct channel *channel)
{
	struct channel_type **arr = tal_arr(ctx, struct channel_type *, 0);

	if (!channel->option_static_remotekey)
		tal_arr_expand(&arr, type_static_remotekey(arr));

	return arr;
}

struct channel_type *channel_desired_type(const tal_t *ctx,
					  const struct channel *channel)
{
	/* For now, we just want option_static_remotekey */
	return type_static_remotekey(ctx);
}
#endif /* EXPERIMENTAL_FEATURES */

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
				      &channel->funding),
		       side_to_str(channel->opener),
		       fmt_channel_view(ctx, &channel->view[LOCAL]),
		       fmt_channel_view(ctx, &channel->view[REMOTE]));
}
/* Magic comment. */
REGISTER_TYPE_TO_STRING(channel, fmt_channel);
