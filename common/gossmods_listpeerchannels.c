#include "config.h"
#include <ccan/err/err.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/node_id.h>
#include <plugins/libplugin.h>

void gossmod_add_localchan(struct gossmap_localmods *mods,
			   const struct node_id *self,
			   const struct node_id *peer,
			   const struct short_channel_id_dir *scidd,
			   struct amount_msat capacity_msat,
			   struct amount_msat htlcmin,
			   struct amount_msat htlcmax,
			   struct amount_msat spendable,
			   struct amount_msat fee_base,
			   u32 fee_proportional,
			   u16 cltv_delta,
			   bool enabled,
			   const char *buf UNUSED,
			   const jsmntok_t *chantok UNUSED,
			   void *cbarg UNUSED)
{
	struct amount_msat min = htlcmin, max = htlcmax;

	if (amount_msat_less(spendable, max))
		max = spendable;

	/* FIXME: features? */
	gossmap_local_addchan(mods, self, peer, scidd->scid, NULL);

	gossmap_local_updatechan(mods, scidd,
				 &enabled,
				 &min, &max,
				 &fee_base,
				 &fee_proportional,
				 &cltv_delta);
}

struct gossmap_localmods *
gossmods_from_listpeerchannels_(const tal_t *ctx,
				const struct node_id *self,
				const char *buf,
				const jsmntok_t *toks,
				bool zero_rates,
				void (*cb)(struct gossmap_localmods *mods,
					   const struct node_id *self,
					   const struct node_id *peer,
					   const struct short_channel_id_dir *scidd,
					   struct amount_msat capacity_msat,
					   struct amount_msat htlcmin,
					   struct amount_msat htlcmax,
					   struct amount_msat sr_able,
					   struct amount_msat fee_base,
					   u32 fee_proportional,
					   u16 cltv_delta,
					   bool enabled,
					   const char *buf,
					   const jsmntok_t *chantok,
					   void *cbarg),
				void *cbarg)
{
	struct gossmap_localmods *mods = gossmap_localmods_new(ctx);
	const jsmntok_t *channels, *channel;
	size_t i;

	channels = json_get_member(buf, toks, "channels");
	json_for_each_arr(i, channel, channels) {
		struct short_channel_id_dir scidd;
		struct short_channel_id alias;
		bool enabled;
		struct node_id dst;
		struct amount_msat capacity_msat, spendable, receivable, fee_base[NUM_SIDES], htlc_min[NUM_SIDES], htlc_max[NUM_SIDES];
		u32 fee_proportional[NUM_SIDES], cltv_delta[NUM_SIDES];
		const char *state, *err;

		/* scid/direction and alias may not exist. */
		scidd.scid.u64 = 0;
		alias.u64 = 0;

		/* We do this to note if we have no remote update. */
		fee_proportional[REMOTE] = -1U;

		err = json_scan(tmpctx, buf, channel,
				"{short_channel_id?:%,"
				"direction?:%,"
				"spendable_msat?:%,"
				"receivable_msat?:%,"
				"peer_connected:%,"
				"state:%,"
				"peer_id:%,"
				"total_msat?:%,"
				"updates?:{"
				 "local"
				 ":{fee_base_msat:%,"
				 "fee_proportional_millionths:%,"
				 "htlc_minimum_msat:%,"
				 "htlc_maximum_msat:%,"
				 "cltv_expiry_delta:%},"
				 "remote?"
				 ":{fee_base_msat:%,"
				 "fee_proportional_millionths:%,"
				 "htlc_minimum_msat:%,"
				 "htlc_maximum_msat:%,"
				 "cltv_expiry_delta:%}},"
				"alias?:{local:%}}",
				JSON_SCAN(json_to_short_channel_id, &scidd.scid),
				JSON_SCAN(json_to_int, &scidd.dir),
				JSON_SCAN(json_to_msat, &spendable),
				JSON_SCAN(json_to_msat, &receivable),
				JSON_SCAN(json_to_bool, &enabled),
				JSON_SCAN_TAL(tmpctx, json_strdup, &state),
				JSON_SCAN(json_to_node_id, &dst),
				JSON_SCAN(json_to_msat, &capacity_msat),
				JSON_SCAN(json_to_msat, &fee_base[LOCAL]),
				JSON_SCAN(json_to_u32, &fee_proportional[LOCAL]),
				JSON_SCAN(json_to_msat, &htlc_min[LOCAL]),
				JSON_SCAN(json_to_msat, &htlc_max[LOCAL]),
				JSON_SCAN(json_to_u32, &cltv_delta[LOCAL]),
				JSON_SCAN(json_to_msat, &fee_base[REMOTE]),
				JSON_SCAN(json_to_u32, &fee_proportional[REMOTE]),
				JSON_SCAN(json_to_msat, &htlc_min[REMOTE]),
				JSON_SCAN(json_to_msat, &htlc_max[REMOTE]),
				JSON_SCAN(json_to_u32, &cltv_delta[REMOTE]),
				JSON_SCAN(json_to_short_channel_id, &alias));
		if (err) {
			errx(1, "Bad listpeerchannels.channels %zu: %s",
			     i, err);
		}

		/* Use alias if no scid.  Note: if alias is set, direction is present */
		if (scidd.scid.u64 == 0 && alias.u64 != 0)
			scidd.scid = alias;

		/* Unusable if no scid (yet) */
		if (scidd.scid.u64 == 0)
			continue;

		/* Disable if in bad state (it's already false if not connected) */
		if (!streq(state, "CHANNELD_NORMAL")
		      && !streq(state, "CHANNELD_AWAITING_SPLICE"))
			enabled = false;

		/* We route better if we know we won't charge
		 * ourselves fees (though if fees are a signal on what
		 * channel we prefer to use, this ignores that
		 * signal!) */
		if (zero_rates) {
			fee_base[LOCAL] = AMOUNT_MSAT(0);
			fee_proportional[LOCAL] = 0;
			cltv_delta[LOCAL] = 0;
		}

		/* We add both directions */
		cb(mods, self, &dst, &scidd, capacity_msat,
		   htlc_min[LOCAL], htlc_max[LOCAL],
		   spendable, fee_base[LOCAL], fee_proportional[LOCAL],
		   cltv_delta[LOCAL], enabled, buf, channel, cbarg);

		/* If we didn't have a remote update, it's not usable yet */
		if (fee_proportional[REMOTE] == -1U)
			continue;

		scidd.dir = !scidd.dir;

		cb(mods, self, &dst, &scidd, capacity_msat,
		   htlc_min[REMOTE], htlc_max[REMOTE],
		   receivable, fee_base[REMOTE], fee_proportional[REMOTE],
		   cltv_delta[REMOTE], enabled, buf, channel, cbarg);
	}

	return mods;
}

