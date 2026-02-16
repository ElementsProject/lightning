#ifndef LIGHTNING_PLUGINS_RENEPAY_DISABLEDMAP_H
#define LIGHTNING_PLUGINS_RENEPAY_DISABLEDMAP_H

#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/bitmap/bitmap.h>
#include <ccan/htable/htable_type.h>
#include <common/gossmap.h>
#include <common/node_id.h>

static inline const struct short_channel_id_dir *
self_scidd(const struct short_channel_id_dir *self)
{
	return self;
}

/* A htable for short_channel_id_dir, the structure itself is the element key.
 */
HTABLE_DEFINE_NODUPS_TYPE(struct short_channel_id_dir, self_scidd, hash_scidd,
			  short_channel_id_dir_eq, scidd_map);

struct disabledmap {
	/* Channels we decided to disable for various reasons. */
	struct scidd_map *disabled_map;
	tal_t *disabled_ctx;

	/* Channels that we flagged for failures. If warned two times we will
	 * disable it. */
	struct scidd_map *warned_map;
	tal_t *warned_ctx;

	/* nodes we disable */
	// FIXME: use a map also for nodes
	struct node_id *disabled_nodes;
};

void disabledmap_reset(struct disabledmap *p);
struct disabledmap *disabledmap_new(const tal_t *ctx);
void disabledmap_add_channel(struct disabledmap *p,
			     struct short_channel_id_dir scidd);
void disabledmap_warn_channel(struct disabledmap *p,
			      struct short_channel_id_dir scidd);
void disabledmap_add_node(struct disabledmap *p, struct node_id node);
bool disabledmap_channel_is_warned(struct disabledmap *p,
				   struct short_channel_id_dir scidd);
bitmap *tal_disabledmap_get_bitmap(const tal_t *ctx, struct disabledmap *p,
				   const struct gossmap *gossmap);

#endif /* LIGHTNING_PLUGINS_RENEPAY_DISABLEDMAP_H */
