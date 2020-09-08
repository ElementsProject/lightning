/* Code for routehints to be inserted into invoices and offers */
#ifndef LIGHTNING_LIGHTNINGD_ROUTEHINT_H
#define LIGHTNING_LIGHTNINGD_ROUTEHINT_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <stdbool.h>

struct lightningd;
struct short_channel_id;

struct routehint_candidate {
	struct route_info *r;
	struct channel *c;
	struct amount_msat capacity;
};

/**
 * routehint_candidates - get possible incoming channels for routehinting.
 * @ctx: tal context to allocate return off
 * @ld: lightningd
 * @incoming_channels_reply: reply from gossipd get_incoming_channels
 * @expose_all_private: consider private channels too (otherwise iff no public)
 * @hints: only consider these channels (if !expose_all_private).
 * @none_public: set to true if we used private channels because none were public.
 * @deadends: set to true if we found a dead-end channel.
 * @amount_offline: amount we didn't consider due to offline channels.
 */
struct routehint_candidate *
routehint_candidates(const tal_t *ctx,
		     struct lightningd *ld,
		     const u8 *incoming_channels_reply,
		     bool expose_all_private,
		     const struct short_channel_id *hints,
		     bool *none_public,
		     bool *deadends,
		     struct amount_msat *amount_offline);

#endif /* LIGHTNING_LIGHTNINGD_ROUTEHINT_H */
