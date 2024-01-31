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
};

#endif /* LIGHTNING_LIGHTNINGD_CLOSED_CHANNEL_H */
