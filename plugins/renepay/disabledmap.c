#include "config.h"
#include <plugins/renepay/disabledmap.h>

struct disabledmap *disabledmap_new(const tal_t *ctx)
{
	struct disabledmap *obj = tal(ctx, struct disabledmap);
	if (!obj)
		return NULL;

	obj->disabled_map = tal(obj, struct scidd_map);
	obj->warned_map = tal(obj, struct scidd_map);
	obj->disabled_ctx = tal(obj, tal_t);
	obj->warned_ctx = tal(obj, tal_t);
	obj->disabled_nodes = tal_arr(obj, struct node_id, 0);

	if (!obj->disabled_map || !obj->warned_map || !obj->disabled_nodes ||
	    !obj->disabled_ctx || !obj->warned_ctx)
		return tal_free(obj);

	scidd_map_init(obj->disabled_map);
	scidd_map_init(obj->warned_map);
	return obj;
}

// FIXME: check success
void disabledmap_reset(struct disabledmap *p)
{
	/* This will remove and free every element in the maps. */
	p->warned_ctx = tal_free(p->warned_ctx);
	p->disabled_ctx = tal_free(p->disabled_ctx);

	tal_resize(&p->disabled_nodes, 0);

	p->disabled_ctx = tal(p, tal_t);
	p->warned_ctx = tal(p, tal_t);
}

static void remove_scidd(struct short_channel_id_dir *scidd,
			 struct scidd_map *map)
{
	scidd_map_del(map, scidd);
}

// FIXME: check success
void disabledmap_add_channel(struct disabledmap *p,
			     struct short_channel_id_dir scidd)
{
	struct short_channel_id_dir *ptr_scidd =
	    scidd_map_get(p->disabled_map, scidd);
	if (ptr_scidd) {
		/* htable allows for duplicates, but we don't want duplicates.
		 */
		return;
	}
	ptr_scidd =
	    tal_dup(p->disabled_ctx, struct short_channel_id_dir, &scidd);
	scidd_map_add(p->disabled_map, ptr_scidd);
	tal_add_destructor2(ptr_scidd, remove_scidd, p->disabled_map);
}

// FIXME: check success
void disabledmap_warn_channel(struct disabledmap *p,
			      struct short_channel_id_dir scidd)
{
	struct short_channel_id_dir *ptr_scidd =
	    scidd_map_get(p->warned_map, scidd);
	if (ptr_scidd) {
		/* htable allows for duplicates, but we don't want duplicates.
		 */
		return;
	}
	ptr_scidd = tal_dup(p->warned_ctx, struct short_channel_id_dir, &scidd);
	scidd_map_add(p->warned_map, ptr_scidd);
	tal_add_destructor2(ptr_scidd, remove_scidd, p->warned_map);
}

// FIXME: check success
void disabledmap_add_node(struct disabledmap *p, struct node_id node)
{
	tal_arr_expand(&p->disabled_nodes, node);
}

bool disabledmap_channel_is_warned(struct disabledmap *p,
				   struct short_channel_id_dir scidd)
{
	return scidd_map_get(p->warned_map, scidd) != NULL;
}

bitmap *tal_disabledmap_get_bitmap(const tal_t *ctx, struct disabledmap *p,
				   const struct gossmap *gossmap)
{
	bitmap *disabled = tal_arrz(
	    ctx, bitmap, 2 * BITMAP_NWORDS(gossmap_max_chan_idx(gossmap)));
	if (!disabled)
		return NULL;

	/* Disable every channel in the list of disabled scids. */
	struct scidd_map_iter it;
	for(struct short_channel_id_dir *scidd = scidd_map_first(p->disabled_map,&it);
		scidd;
		scidd = scidd_map_next(p->disabled_map, &it)){

		struct gossmap_chan *c =
		    gossmap_find_chan(gossmap, &scidd->scid);
		if (c)
			bitmap_set_bit(disabled,
				       gossmap_chan_idx(gossmap, c) * 2 +
					   scidd->dir);
	}

	/* Disable all channels that lead to a disabled node. */
	for (size_t i = 0; i < tal_count(p->disabled_nodes); i++) {
		const struct gossmap_node *node =
		    gossmap_find_node(gossmap, &p->disabled_nodes[i]);

		for (size_t j = 0; j < node->num_chans; j++) {
			int half;
			const struct gossmap_chan *c =
			    gossmap_nth_chan(gossmap, node, j, &half);
			bitmap_set_bit(disabled,
				       gossmap_chan_idx(gossmap, c) * 2 + half);
		}
	}
	return disabled;
}
