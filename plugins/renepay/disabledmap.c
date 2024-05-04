#include "config.h"
#include <plugins/renepay/disabledmap.h>

struct disabledmap *disabledmap_new(const tal_t *ctx)
{
	struct disabledmap *obj = tal(ctx, struct disabledmap);
	if (!obj)
		return NULL;

	obj->disabled_scids = tal_arr(obj, struct short_channel_id, 0);
	obj->warned_scids = tal_arr(obj, struct short_channel_id, 0);
	obj->disabled_nodes = tal_arr(obj, struct node_id, 0);

	if (!obj->disabled_scids || !obj->warned_scids || !obj->disabled_nodes)
		return tal_free(obj);
	return obj;
}

// FIXME: check success
void disabledmap_reset(struct disabledmap *p)
{
	tal_resize(&p->disabled_scids, 0);
	tal_resize(&p->warned_scids, 0);
	tal_resize(&p->disabled_nodes, 0);
}

// FIXME: check success
void disabledmap_add_channel(struct disabledmap *p,
			     struct short_channel_id scid)
{
	tal_arr_expand(&p->disabled_scids, scid);
}

// FIXME: check success
void disabledmap_warn_channel(struct disabledmap *p,
			      struct short_channel_id scid)
{
	tal_arr_expand(&p->warned_scids, scid);
}

// FIXME: check success
void disabledmap_add_node(struct disabledmap *p, struct node_id node)
{
	tal_arr_expand(&p->disabled_nodes, node);
}

bool disabledmap_channel_is_warned(struct disabledmap *p,
				   struct short_channel_id scid)
{
	for (size_t i = 0; i < tal_count(p->warned_scids); i++) {
		if (short_channel_id_eq(scid, p->warned_scids[i]))
			return true;
	}
	return false;
}

bitmap *tal_disabledmap_get_bitmap(const tal_t *ctx, struct disabledmap *p,
				   const struct gossmap *gossmap)
{
	bitmap *disabled =
	    tal_arrz(ctx, bitmap, BITMAP_NWORDS(gossmap_max_chan_idx(gossmap)));
	if (!disabled)
		return NULL;

	/* Disable every channel in the list of disabled scids. */
	for (size_t i = 0; i < tal_count(p->disabled_scids); i++) {
		struct gossmap_chan *c =
		    gossmap_find_chan(gossmap, &p->disabled_scids[i]);
		if (c)
			bitmap_set_bit(disabled, gossmap_chan_idx(gossmap, c));
	}

	/* Disable all channels that lead to a disabled node. */
	for (size_t i = 0; i < tal_count(p->disabled_nodes); i++) {
		const struct gossmap_node *node =
		    gossmap_find_node(gossmap, &p->disabled_nodes[i]);

		for (size_t j = 0; j < node->num_chans; j++) {
			int half;
			const struct gossmap_chan *c =
			    gossmap_nth_chan(gossmap, node, j, &half);
			bitmap_set_bit(disabled, gossmap_chan_idx(gossmap, c));
		}
	}
	return disabled;
}
