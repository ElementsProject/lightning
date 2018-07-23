#include <assert.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/initial_channel.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/type_to_string.h>
#include <inttypes.h>

struct channel *new_initial_channel(const tal_t *ctx,
				    const struct bitcoin_txid *funding_txid,
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
	channel->htlcs = NULL;
	channel->changes_pending[LOCAL] = channel->changes_pending[REMOTE]
		= false;

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

	return channel;
}

/* FIXME: We could cache this. */
struct bitcoin_tx *initial_channel_tx(const tal_t *ctx,
				      const u8 **wscript,
				      const struct channel *channel,
				      const struct pubkey *per_commitment_point,
				      enum side side)
{
	struct keyset keyset;

	/* This assumes no HTLCs! */
	assert(!channel->htlcs);

	if (!derive_keyset(per_commitment_point,
			   &channel->basepoints[side],
			   &channel->basepoints[!side],
			   &keyset))
		return NULL;

	*wscript = bitcoin_redeem_2of2(ctx,
				       &channel->funding_pubkey[side],
				       &channel->funding_pubkey[!side]);

	return initial_commit_tx(ctx, &channel->funding_txid,
				 channel->funding_txout,
				 channel->funding_msat / 1000,
				 channel->funder,
				 to_self_delay(channel, side),
				 &keyset,
				 channel->view[side].feerate_per_kw,
				 dust_limit_satoshis(channel, side),
				 channel->view[side].owed_msat[side],
				 channel->view[side].owed_msat[!side],
				 channel_reserve_msat(channel, side),
				 0 ^ channel->commitment_number_obscurer,
				 side);
}

static char *fmt_channel_view(const tal_t *ctx, const struct channel_view *view)
{
	return tal_fmt(ctx, "{ feerate_per_kw=%"PRIu32","
		       " owed_local=%"PRIu64","
		       " owed_remote=%"PRIu64" }",
		       view->feerate_per_kw,
		       view->owed_msat[LOCAL],
		       view->owed_msat[REMOTE]);
}

/* FIXME: This should reference HTLCs somehow. */
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
