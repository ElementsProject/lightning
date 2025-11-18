/* Not to be confused with live channels in ld->channels */
#ifndef LIGHTNING_LIGHTNINGD_CLOSED_CHANNEL_H
#define LIGHTNING_LIGHTNINGD_CLOSED_CHANNEL_H
#include "config.h"
#include <bitcoin/tx.h>
#include <common/channel_id.h>
#include <common/htlc.h>
#include <lightningd/channel_state.h>

struct closed_channel {
	/* This is often deleted on older nodes! */
	struct node_id *peer_id;
	struct channel_id cid;
	struct short_channel_id *scid;
	struct short_channel_id *alias[NUM_SIDES];
	enum side opener, closer;
	u8 channel_flags;
	u64 next_index[NUM_SIDES], next_htlc_id;
	struct bitcoin_outpoint funding;
	struct amount_sat funding_sats;
	struct amount_msat push;
	struct amount_msat our_msat;
	/* Statistics for min and max our_msatoshi. */
	struct amount_msat msat_to_us_min;
	struct amount_msat msat_to_us_max;
	struct bitcoin_tx *last_tx;
	const struct channel_type *type;
	enum state_change state_change_cause;
	bool leased;
	u64 last_stable_connection;
	/* NULL for older closed channels */
	const struct shachain *their_shachain;
	const struct wally_psbt *funding_psbt;
	bool withheld;
};

static inline const struct channel_id *keyof_closed_channel(const struct closed_channel *cc)
{
	return &cc->cid;
}

size_t hash_cid(const struct channel_id *cid);

static inline bool closed_channel_eq_cid(const struct closed_channel *cc, const struct channel_id *cid)
{
	return channel_id_eq(cid, &cc->cid);
}

HTABLE_DEFINE_NODUPS_TYPE(struct closed_channel, keyof_closed_channel, hash_cid, closed_channel_eq_cid,
			  closed_channel_map);

#endif /* LIGHTNING_LIGHTNINGD_CLOSED_CHANNEL_H */
