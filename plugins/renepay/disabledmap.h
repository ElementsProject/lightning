#ifndef LIGHTNING_PLUGINS_RENEPAY_DISABLEDMAP_H
#define LIGHTNING_PLUGINS_RENEPAY_DISABLEDMAP_H

#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/bitmap/bitmap.h>
#include <common/gossmap.h>
#include <common/node_id.h>

struct disabledmap {
	/* Channels we decided to disable for various reasons. */
	/* FIXME: disabled_scids should be a set rather than an array, so that
	 * we don't have to worry about disabling the same channel multiple
	 * times. */
	struct short_channel_id *disabled_scids;

	/* Channels that we flagged for failures. If warned two times we will
	 * disable it. */
	struct short_channel_id *warned_scids;

	/* nodes we disable */
	struct node_id *disabled_nodes;
};

void disabledmap_reset(struct disabledmap *p);
struct disabledmap *disabledmap_new(const tal_t *ctx);
void disabledmap_add_channel(struct disabledmap *p,
			     struct short_channel_id scid);
void disabledmap_warn_channel(struct disabledmap *p,
			      struct short_channel_id scid);
void disabledmap_add_node(struct disabledmap *p, struct node_id node);
bool disabledmap_channel_is_warned(struct disabledmap *p,
				   struct short_channel_id scid);
bitmap *tal_disabledmap_get_bitmap(const tal_t *ctx, struct disabledmap *p,
				   const struct gossmap *gossmap);

#endif /* LIGHTNING_PLUGINS_RENEPAY_DISABLEDMAP_H */
