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

/* Look up a layer by name. */
struct layer *find_layer(struct askrene *askrene, const char *name);

/* Create new layer by name. */
struct layer *new_layer(struct askrene *askrene, const char *name TAKES, bool persistent);

/* New temporary layer (not in askrene's hash table) */
struct layer *new_temp_layer(const tal_t *ctx, struct askrene *askrene, const char *name TAKES);

/* Remove this layer. */
void remove_layer(struct layer *layer);

/* Get the name of the layer */
const char *layer_name(const struct layer *layer);

/* Find a local channel in a layer */
const struct local_channel *layer_find_local_channel(const struct layer *layer,
						     struct short_channel_id scid);

/* Get capacity of that channel. */
struct amount_msat local_channel_capacity(const struct local_channel *lc);

/* Load any persistent layers */
void load_layers(struct askrene *askrene, struct command *init_cmd);

/* Check local channel matches these */
bool layer_check_local_channel(const struct local_channel *lc,
			       const struct node_id *n1,
			       const struct node_id *n2,
			       struct amount_msat capacity);

/* Add a local channel to a layer! */
void layer_add_local_channel(struct layer *layer,
			     const struct node_id *src,
			     const struct node_id *dst,
			     struct short_channel_id scid,
			     struct amount_msat capacity);

/* Add/set a bias for this layer.  Returns NULL if bias_factor is 0. */
const struct bias *layer_set_bias(struct layer *layer,
				  const struct short_channel_id_dir *scidd,
				  const char *description TAKES,
				  s8 bias_factor,
				  bool relative);

/* Update details on a channel (could be in this layer, or another) */
void layer_add_update_channel(struct layer *layer,
			      const struct short_channel_id_dir *scidd,
			      const bool *enabled,
			      const struct amount_msat *htlc_min,
			      const struct amount_msat *htlc_max,
			      const struct amount_msat *base_fee,
			      const u32 *proportional_fee,
			      const u16 *delay);

/* If any capacities of channels are limited, unset the corresponding element in
 * the capacities[] array */
void layer_clear_overridden_capacities(const struct layer *layer,
				       const struct gossmap *gossmap,
				       fp16_t *capacities);

/* Apply constraints from a layer (reduce min, increase max). */
void layer_apply_constraints(const struct layer *layer,
			     const struct short_channel_id_dir *scidd,
			     struct amount_msat *min,
			     struct amount_msat *max)
	NO_NULL_ARGS;

/* Apply biases from a layer. */
void layer_apply_biases(const struct layer *layer,
			const struct gossmap *gossmap,
			s8 *biases);

/* Add one or more constraints on a layer. */
const struct constraint *layer_add_constraint(struct layer *layer,
					      const struct short_channel_id_dir *scidd,
					      u64 timestamp,
					      const struct amount_msat *min,
					      const struct amount_msat *max);

/* Add local channels from this layer. */
void layer_add_localmods(const struct layer *layer,
			 const struct gossmap *gossmap,
			 struct gossmap_localmods *localmods);

/* Remove constraints older then cutoff: returns num removed. */
size_t layer_trim_constraints(struct layer *layer, u64 cutoff);

/* Add a disabled node to a layer. */
void layer_add_disabled_node(struct layer *layer, const struct node_id *node);

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

/* Print a single bias */
void json_add_bias(struct json_stream *js,
		   const char *fieldname,
		   const struct bias *b,
		   const struct layer *layer);

/* For explain_failure: did this layer create this scid? */
bool layer_created(const struct layer *layer, struct short_channel_id scid);

/* For explain_failure: did this layer disable this channel? */
bool layer_disables_chan(const struct layer *layer, const struct short_channel_id_dir *scidd);

/* For explain_failure: did this layer disable this node? */
bool layer_disables_node(const struct layer *layer, const struct node_id *node);

/* Scan for memleaks */
void layer_memleak_mark(struct askrene *askrene, struct htable *memtable);
#endif /* LIGHTNING_PLUGINS_ASKRENE_LAYER_H */
