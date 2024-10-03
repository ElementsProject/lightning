#ifndef LIGHTNING_PLUGINS_ASKRENE_LAYER_H
#define LIGHTNING_PLUGINS_ASKRENE_LAYER_H
/* A layer is the group of information maintained by askrene.  The caller
 * specifies which layers to use when asking for a route, and tell askrene
 * what layer to add new information to.
 *
 * Layers can be used to shape local decisions (for this payment, add these
 * connections, or disable all connections to this node).  You can also,
 * in theory, export a layer, or import a layer from another source, to see
 * what the results are when that layer is included. */
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <common/amount.h>
#include <common/node_id.h>

struct askrene;
struct layer;
struct json_stream;

/* A constraint reflects something we learned about a channel */
struct constraint {
	struct short_channel_id_dir scidd;
	/* Time this constraint was last updated */
	u64 timestamp;
	/* Non-zero means set */
	struct amount_msat min;
	/* Non-0xFFFFF.... means set */
	struct amount_msat max;
};

/* Look up a layer by name. */
struct layer *find_layer(struct askrene *askrene, const char *name);

/* Create new layer by name. */
struct layer *new_layer(struct askrene *askrene, const char *name);

/* New temporary layer (not in askrene's hash table) */
struct layer *new_temp_layer(const tal_t *ctx, const char *name);

/* Get the name of the layer */
const char *layer_name(const struct layer *layer);

/* Find a local channel in a layer */
const struct local_channel *layer_find_local_channel(const struct layer *layer,
						     struct short_channel_id scid);

/* Get capacity of that channel. */
struct amount_msat local_channel_capacity(const struct local_channel *lc);

/* Check local channel matches these */
bool layer_check_local_channel(const struct local_channel *lc,
			       const struct node_id *n1,
			       const struct node_id *n2,
			       struct amount_msat capacity);

/* Update a local channel to a layer: fails if you try to change capacity or nodes! */
void layer_update_local_channel(struct layer *layer,
				const struct node_id *src,
				const struct node_id *dst,
				struct short_channel_id scid,
				struct amount_msat capacity,
				struct amount_msat base_fee,
				u32 proportional_fee,
				u16 delay,
				struct amount_msat htlc_min,
				struct amount_msat htlc_max);

/* If any capacities of channels are limited, unset the corresponding element in
 * the capacities[] array */
void layer_clear_overridden_capacities(const struct layer *layer,
				       const struct gossmap *gossmap,
				       fp16_t *capacities);

/* Find a constraint in a layer. */
const struct constraint *layer_find_constraint(const struct layer *layer,
					       const struct short_channel_id_dir *scidd);

/* Add/update one or more constraints on a layer. */
const struct constraint *layer_update_constraint(struct layer *layer,
						 const struct short_channel_id_dir *scidd,
						 u64 timestamp,
						 const struct amount_msat *min,
						 const struct amount_msat *max);

/* Add local channels from this layer.  zero_cost means set fees and delay to 0. */
void layer_add_localmods(const struct layer *layer,
			 const struct gossmap *gossmap,
			 bool zero_cost,
			 struct gossmap_localmods *localmods);

/* Remove constraints older then cutoff: returns num removed. */
size_t layer_trim_constraints(struct layer *layer, u64 cutoff);

/* Add a disabled node to a layer. */
void layer_add_disabled_node(struct layer *layer, const struct node_id *node);

/* Add a disabled channel to a layer. */
void layer_add_disabled_channel(struct layer *layer,
				const struct short_channel_id_dir *scidd);

/* Print out a json object for this layer, or all if layer is NULL */
void json_add_layers(struct json_stream *js,
		     struct askrene *askrene,
		     const char *fieldname,
		     const struct layer *layer);

/* Print a single constraint */
void json_add_constraint(struct json_stream *js,
			 const char *fieldname,
			 const struct constraint *c,
			 const struct layer *layer);

/* Scan for memleaks */
void layer_memleak_mark(struct askrene *askrene, struct htable *memtable);
#endif /* LIGHTNING_PLUGINS_ASKRENE_LAYER_H */
