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
 * @buf, @toks: output of listincoming command
 * @expose_all_private: trinary.  NULL=iff no public, true=always, false=never.
 * @hints: only consider these channels (if !expose_all_private).
 * @none_public: set to true if we used private channels because none were public.
 * @avail_capacity: total capacity of usable channels.
 * @private_capacity: total capacity of unused private channels.
 * @deadend_capacity: total capacity of "deadend" channels.
 * @offline_capacity: total capacity of offline channels.
 */
struct routehint_candidate *
routehint_candidates(const tal_t *ctx,
		     struct lightningd *ld,
		     const char *buf,
		     const jsmntok_t *toks,
		     const bool *expose_all_private,
		     const struct short_channel_id *hints,
		     bool *none_public,
		     struct amount_msat *avail_capacity,
		     struct amount_msat *private_capacity,
		     struct amount_msat *deadend_capacity,
		     struct amount_msat *offline_capacity);

#endif /* LIGHTNING_LIGHTNINGD_ROUTEHINT_H */
