#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/layer.h>

/* A channels which doesn't (necessarily) exist in the gossmap. */
struct local_channel {
	/* Canonical order, n1 < n2 */
	struct node_id n1, n2;
	struct short_channel_id scid;
	struct amount_msat capacity;
};

struct local_update {
	struct short_channel_id_dir scidd;

	/* Non-null fields apply. */
	const bool *enabled;
	const u16 *delay;
	const u32 *proportional_fee;
	const struct amount_msat *base_fee;
	const struct amount_msat *htlc_min, *htlc_max;
};

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

static const struct short_channel_id_dir *
constraint_scidd(const struct constraint *c)
{
	return &c->scidd;
}

static inline bool constraint_eq_scidd(const struct constraint *c,
				       const struct short_channel_id_dir *scidd)
{
	return short_channel_id_dir_eq(scidd, &c->scidd);
}

HTABLE_DEFINE_TYPE(struct constraint, constraint_scidd, hash_scidd,
		   constraint_eq_scidd, constraint_hash);

static struct short_channel_id
local_channel_scid(const struct local_channel *lc)
{
	return lc->scid;
}

static size_t hash_scid(const struct short_channel_id scid)
{
	/* scids cost money to generate, so simple hash works here */
	return (scid.u64 >> 32) ^ (scid.u64 >> 16) ^ scid.u64;
}

static inline bool local_channel_eq_scid(const struct local_channel *lc,
					 const struct short_channel_id scid)
{
	return short_channel_id_eq(scid, lc->scid);
}

HTABLE_DEFINE_TYPE(struct local_channel, local_channel_scid, hash_scid,
		   local_channel_eq_scid, local_channel_hash);

static const struct short_channel_id_dir *
local_update_scidd(const struct local_update *lu)
{
	return &lu->scidd;
}

static inline bool local_update_eq_scidd(const struct local_update *lu,
					 const struct short_channel_id_dir *scidd)
{
	return short_channel_id_dir_eq(scidd, &lu->scidd);
}

HTABLE_DEFINE_TYPE(struct local_update, local_update_scidd, hash_scidd,
		   local_update_eq_scidd, local_update_hash);

struct layer {
	/* Inside global list of layers */
	struct list_node list;

	/* Unique identifiers */
	const char *name;

	/* Completely made up local additions, indexed by scid */
	struct local_channel_hash *local_channels;

	/* Modifications to channels, indexed by scidd */
	struct local_update_hash *local_updates;

	/* Additional info, indexed by scid+dir */
	struct constraint_hash *constraints;

	/* Nodes to completely disable (tal_arr) */
	struct node_id *disabled_nodes;
};

struct layer *new_temp_layer(const tal_t *ctx, const char *name)
{
	struct layer *l = tal(ctx, struct layer);

	l->name = tal_strdup(l, name);
	l->local_channels = tal(l, struct local_channel_hash);
	local_channel_hash_init(l->local_channels);
	l->local_updates = tal(l, struct local_update_hash);
	local_update_hash_init(l->local_updates);
	l->constraints = tal(l, struct constraint_hash);
	constraint_hash_init(l->constraints);
	l->disabled_nodes = tal_arr(l, struct node_id, 0);

	return l;
}

static void destroy_layer(struct layer *l, struct askrene *askrene)
{
	list_del_from(&askrene->layers, &l->list);
}

struct layer *new_layer(struct askrene *askrene, const char *name)
{
	struct layer *l = new_temp_layer(askrene, name);
	list_add(&askrene->layers, &l->list);
	tal_add_destructor2(l, destroy_layer, askrene);
	return l;
}

struct layer *find_layer(struct askrene *askrene, const char *name)
{
	struct layer *l;
	list_for_each(&askrene->layers, l, list) {
		if (streq(l->name, name))
			return l;
	}
	return NULL;
}

const char *layer_name(const struct layer *layer)
{
	return layer->name;
}

static struct local_channel *new_local_channel(struct layer *layer,
					       const struct node_id *n1,
					       const struct node_id *n2,
					       struct short_channel_id scid,
					       struct amount_msat capacity)
{
	struct local_channel *lc = tal(layer, struct local_channel);

	/* Swap if necessary to make into BOLT-7 order. */
	if (node_id_cmp(n1, n2) < 0) {
		lc->n1 = *n1;
		lc->n2 = *n2;
	} else {
		lc->n1 = *n2;
		lc->n2 = *n1;
	}
	lc->scid = scid;
	lc->capacity = capacity;

	local_channel_hash_add(layer->local_channels, lc);
	return lc;
}

void layer_add_local_channel(struct layer *layer,
			     const struct node_id *src,
			     const struct node_id *dst,
			     struct short_channel_id scid,
			     struct amount_msat capacity)
{
	assert(!local_channel_hash_get(layer->local_channels, scid));
	new_local_channel(layer, src, dst, scid, capacity);
}

void layer_add_update_channel(struct layer *layer,
			      const struct short_channel_id_dir *scidd,
			      const bool *enabled,
			      const struct amount_msat *htlc_min,
			      const struct amount_msat *htlc_max,
			      const struct amount_msat *base_fee,
			      const u32 *proportional_fee,
			      const u16 *delay)
{
	struct local_update *lu;

	lu = local_update_hash_get(layer->local_updates, scidd);
	if (!lu) {
		lu = tal(layer, struct local_update);
		lu->scidd = *scidd;
		lu->enabled = NULL;
		lu->delay = NULL;
		lu->proportional_fee = NULL;
		lu->base_fee = lu->htlc_min = lu->htlc_max = NULL;
		local_update_hash_add(layer->local_updates, lu);
	}
	if (enabled) {
		tal_free(lu->enabled);
		lu->enabled = tal_dup(lu, bool, enabled);
	}
	if (htlc_min) {
		tal_free(lu->htlc_min);
		lu->htlc_min = tal_dup(lu, struct amount_msat, htlc_min);
	}
	if (htlc_max) {
		tal_free(lu->htlc_max);
		lu->htlc_max = tal_dup(lu, struct amount_msat, htlc_max);
	}
	if (base_fee) {
		tal_free(lu->base_fee);
		lu->base_fee = tal_dup(lu, struct amount_msat, base_fee);
	}
	if (proportional_fee) {
		tal_free(lu->proportional_fee);
		lu->proportional_fee = tal_dup(lu, u32, proportional_fee);
	}
	if (delay) {
		tal_free(lu->delay);
		lu->delay = tal_dup(lu, u16, delay);
	}
}

struct amount_msat local_channel_capacity(const struct local_channel *lc)
{
	return lc->capacity;
}

const struct local_channel *layer_find_local_channel(const struct layer *layer,
						     struct short_channel_id scid)
{
	return local_channel_hash_get(layer->local_channels, scid);
}

void layer_apply_constraints(const struct layer *layer,
			     const struct short_channel_id_dir *scidd,
			     struct amount_msat *min,
			     struct amount_msat *max)
{
	struct constraint *c;
	struct constraint_hash_iter cit;

	/* We can have more than one: apply them all! */
	for (c = constraint_hash_getfirst(layer->constraints, scidd, &cit);
	     c;
	     c = constraint_hash_getnext(layer->constraints, scidd, &cit)) {
		if (amount_msat_greater(c->min, *min))
			*min = c->min;
		if (amount_msat_less(c->max, *max))
			*max = c->max;
	}
}

const struct constraint *layer_add_constraint(struct layer *layer,
					      const struct short_channel_id_dir *scidd,
					      u64 timestamp,
					      const struct amount_msat *min,
					      const struct amount_msat *max)
{
	struct constraint *c = tal(layer, struct constraint);
	c->scidd = *scidd;

	if (min)
		c->min = *min;
	else
		c->min = AMOUNT_MSAT(0);
	if (max)
		c->max = *max;
	else
		c->max = AMOUNT_MSAT(UINT64_MAX);
	c->timestamp = timestamp;

	constraint_hash_add(layer->constraints, c);
	return c;
}

void layer_clear_overridden_capacities(const struct layer *layer,
				       const struct gossmap *gossmap,
				       fp16_t *capacities)
{
	struct constraint_hash_iter conit;
	struct constraint *con;

	for (con = constraint_hash_first(layer->constraints, &conit);
	     con;
	     con = constraint_hash_next(layer->constraints, &conit)) {
		struct gossmap_chan *c = gossmap_find_chan(gossmap, &con->scidd.scid);
		size_t idx;
		if (!c)
			continue;
		idx = gossmap_chan_idx(gossmap, c);
		if (idx < tal_count(capacities))
			capacities[idx] = 0;
	}
}

size_t layer_trim_constraints(struct layer *layer, u64 cutoff)
{
	size_t num_removed = 0;
	struct constraint_hash_iter conit;
	struct constraint *con;

	for (con = constraint_hash_first(layer->constraints, &conit);
	     con;
	     con = constraint_hash_next(layer->constraints, &conit)) {
		if (con->timestamp < cutoff) {
			constraint_hash_delval(layer->constraints, &conit);
			tal_free(con);
			num_removed++;
		}
	}
	return num_removed;
}

void layer_add_disabled_node(struct layer *layer, const struct node_id *node)
{
	tal_arr_expand(&layer->disabled_nodes, *node);
}

void layer_add_localmods(const struct layer *layer,
			 const struct gossmap *gossmap,
			 struct gossmap_localmods *localmods)
{
	const struct local_channel *lc;
	struct local_channel_hash_iter lcit;
	const struct local_update *lu;
	struct local_update_hash_iter luit;

	/* First, disable all channels into blocked nodes (local updates
	 * can add new ones)! */
	for (size_t i = 0; i < tal_count(layer->disabled_nodes); i++) {
		const struct gossmap_node *node;

		node = gossmap_find_node(gossmap, &layer->disabled_nodes[i]);
		if (!node)
			continue;
		for (size_t n = 0; n < node->num_chans; n++) {
			struct short_channel_id_dir scidd;
			struct gossmap_chan *c;
			bool enabled = false;
			struct amount_msat zero = AMOUNT_MSAT(0);
			c = gossmap_nth_chan(gossmap, node, n, &scidd.dir);
			scidd.scid = gossmap_chan_scid(gossmap, c);

			/* Disabled zero-capacity on incoming */
			gossmap_local_updatechan(localmods,
						 &scidd,
						 &enabled,
						 &zero, &zero,
						 NULL, NULL, NULL);
		}
	}

	/* Now create new channels */
	for (lc = local_channel_hash_first(layer->local_channels, &lcit);
	     lc;
	     lc = local_channel_hash_next(layer->local_channels, &lcit)) {
		gossmap_local_addchan(localmods,
				      &lc->n1, &lc->n2, lc->scid, lc->capacity,
				      NULL);
	}

	/* Now update channels */
	/* Now modify channels, if they exist */
	for (lu = local_update_hash_first(layer->local_updates, &luit);
	     lu;
	     lu = local_update_hash_next(layer->local_updates, &luit)) {
		gossmap_local_updatechan(localmods, &lu->scidd,
					 lu->enabled,
					 lu->htlc_min,
					 lu->htlc_max,
					 lu->base_fee,
					 lu->proportional_fee,
					 lu->delay);
	}
}

static void json_add_local_channel(struct json_stream *response,
				   const char *fieldname,
				   const struct local_channel *lc)
{
	json_object_start(response, fieldname);
	json_add_node_id(response, "source", &lc->n1);
	json_add_node_id(response, "destination", &lc->n2);
	json_add_short_channel_id(response, "short_channel_id", lc->scid);
	json_add_amount_msat(response, "capacity_msat", lc->capacity);
	json_object_end(response);
}

static void json_add_local_update(struct json_stream *response,
				   const char *fieldname,
				   const struct local_update *lu)
{
	json_object_start(response, fieldname);
	json_add_short_channel_id_dir(response, "short_channel_id_dir",
				      lu->scidd);
	if (lu->enabled)
		json_add_bool(response, "enabled", *lu->enabled);
	if (lu->htlc_min)
		json_add_amount_msat(response,
				     "htlc_minimum_msat", *lu->htlc_min);
	if (lu->htlc_max)
		json_add_amount_msat(response,
				     "htlc_maximum_msat", *lu->htlc_max);
	if (lu->base_fee)
		json_add_amount_msat(response, "fee_base_msat", *lu->base_fee);
	if (lu->proportional_fee)
		json_add_u32(response,
			     "fee_proportional_millionths",
			     *lu->proportional_fee);
	if (lu->delay)
		json_add_u32(response, "cltv_expiry_delta", *lu->delay);
	json_object_end(response);
}

void json_add_constraint(struct json_stream *js,
			 const char *fieldname,
			 const struct constraint *c,
			 const struct layer *layer)
{
	json_object_start(js, fieldname);
	if (layer)
		json_add_string(js, "layer", layer->name);
	json_add_short_channel_id_dir(js, "short_channel_id_dir", c->scidd);
	json_add_u64(js, "timestamp", c->timestamp);
	if (!amount_msat_is_zero(c->min))
		json_add_amount_msat(js, "minimum_msat", c->min);
	if (!amount_msat_eq(c->max, AMOUNT_MSAT(UINT64_MAX)))
		json_add_amount_msat(js, "maximum_msat", c->max);
	json_object_end(js);
}

static void json_add_layer(struct json_stream *js,
			   const char *fieldname,
			   const struct layer *layer)
{
	struct local_channel_hash_iter lcit;
	const struct local_channel *lc;
	const struct local_update *lu;
	struct local_update_hash_iter luit;
	struct constraint_hash_iter conit;
	const struct constraint *c;

	json_object_start(js, fieldname);
	json_add_string(js, "layer", layer->name);
	json_array_start(js, "disabled_nodes");
	for (size_t i = 0; i < tal_count(layer->disabled_nodes); i++)
		json_add_node_id(js, NULL, &layer->disabled_nodes[i]);
	json_array_end(js);
	json_array_start(js, "created_channels");
	for (lc = local_channel_hash_first(layer->local_channels, &lcit);
	     lc;
	     lc = local_channel_hash_next(layer->local_channels, &lcit)) {
		json_add_local_channel(js, NULL, lc);
	}
	json_array_end(js);
	json_array_start(js, "channel_updates");
	for (lu = local_update_hash_first(layer->local_updates, &luit);
	     lu;
	     lu = local_update_hash_next(layer->local_updates, &luit)) {
		json_add_local_update(js, NULL, lu);
	}
	json_array_end(js);
	json_array_start(js, "constraints");
	for (c = constraint_hash_first(layer->constraints, &conit);
	     c;
	     c = constraint_hash_next(layer->constraints, &conit)) {
		/* Don't show ones we generated internally */
		if (c->timestamp == UINT64_MAX)
			continue;
		json_add_constraint(js, NULL, c, NULL);
	}
	json_array_end(js);
	json_object_end(js);
}

void json_add_layers(struct json_stream *js,
		     struct askrene *askrene,
		     const char *fieldname,
		     const struct layer *layer)
{
	struct layer *l;

	json_array_start(js, fieldname);
	list_for_each(&askrene->layers, l, list) {
		if (layer && l != layer)
			continue;
		json_add_layer(js, NULL, l);
	}
	json_array_end(js);
}

bool layer_created(const struct layer *layer, struct short_channel_id scid)
{
	return local_channel_hash_get(layer->local_channels, scid);
}

bool layer_disables(const struct layer *layer,
		    const struct short_channel_id_dir *scidd)
{
	const struct local_update *lu;

	lu = local_update_hash_get(layer->local_updates, scidd);

	return (lu && lu->enabled && *lu->enabled == false);
}

void layer_memleak_mark(struct askrene *askrene, struct htable *memtable)
{
	struct layer *l;
	list_for_each(&askrene->layers, l, list) {
		memleak_scan_htable(memtable, &l->constraints->raw);
		memleak_scan_htable(memtable, &l->local_channels->raw);
	}
}
