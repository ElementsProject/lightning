#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/route.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/layer.h>

/* A channels which doesn't (necessarily) exist in the gossmap. */
struct local_channel {
	/* Canonical order, n1 < n2 */
	struct node_id n1, n2;
	struct short_channel_id scid;
	struct amount_msat capacity;

	struct added_channel_half {
		/* Other fields only valid if this is true */
		bool enabled;
		u16 delay;
		u32 proportional_fee;
		struct amount_msat base_fee;
		struct amount_msat htlc_min, htlc_max;
	} half[2];
};

static const struct constraint_key *
constraint_key(const struct constraint *c)
{
	return &c->key;
}

static size_t hash_constraint_key(const struct constraint_key *key)
{
	/* scids cost money to generate, so simple hash works here */
	return (key->scidd.scid.u64 >> 32) ^ (key->scidd.scid.u64)
		^ (key->scidd.dir << 1) ^ (key->type);
}

static inline bool constraint_eq_key(const struct constraint *c,
				     const struct constraint_key *key)
{
	return short_channel_id_dir_eq(&key->scidd, &c->key.scidd) && key->type == c->key.type;
}

HTABLE_DEFINE_TYPE(struct constraint, constraint_key, hash_constraint_key,
		   constraint_eq_key, constraint_hash);

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

struct layer {
	/* Inside global list of layers */
	struct list_node list;

	/* Unique identifiers */
	const char *name;

	/* Completely made up local additions, indexed by scid */
	struct local_channel_hash *local_channels;

	/* Additional info, indexed by scid+dir */
	struct constraint_hash *constraints;

	/* Channels and nodes to disable (tal_arr). */
	struct route_exclusion *disabled;
};

struct layer *new_temp_layer(const tal_t *ctx, const char *name)
{
	struct layer *l = tal(ctx, struct layer);

	l->name = tal_strdup(l, name);
	l->local_channels = tal(l, struct local_channel_hash);
	local_channel_hash_init(l->local_channels);
	l->constraints = tal(l, struct constraint_hash);
	constraint_hash_init(l->constraints);
	l->disabled = tal_arr(l, struct route_exclusion, 0);

	return l;
}

struct layer *new_layer(struct askrene *askrene, const char *name)
{
	struct layer *l = new_temp_layer(askrene, name);
	list_add(&askrene->layers, &l->list);
	return l;
}

/* Swap if necessary to make into BOLT-7 order.  Return direction. */
static int canonicalize_node_order(const struct node_id **n1,
				   const struct node_id **n2)
{
	const struct node_id *tmp;

	if (node_id_cmp(*n1, *n2) < 0)
		return 0;
	tmp = *n2;
	*n2 = *n1;
	*n1 = tmp;
	return 1;
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
	lc->n1 = *n1;
	lc->n2 = *n2;
	lc->scid = scid;
	lc->capacity = capacity;

	for (size_t i = 0; i < ARRAY_SIZE(lc->half); i++)
		lc->half[i].enabled = false;

	local_channel_hash_add(layer->local_channels, lc);
	return lc;
}

bool layer_check_local_channel(const struct local_channel *lc,
			       const struct node_id *n1,
			       const struct node_id *n2,
			       struct amount_msat capacity)
{
	canonicalize_node_order(&n1, &n2);
	return node_id_eq(&lc->n1, n1)
		&& node_id_eq(&lc->n2, n2)
		&& amount_msat_eq(lc->capacity, capacity);
}

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
				struct amount_msat htlc_max)
{
	struct local_channel *lc = local_channel_hash_get(layer->local_channels, scid);
	int dir = canonicalize_node_order(&src, &dst);
	struct short_channel_id_dir scidd;

	if (lc) {
		assert(layer_check_local_channel(lc, src, dst, capacity));
	} else {
		lc = new_local_channel(layer, src, dst, scid, capacity);
	}

	lc->half[dir].enabled = true;
	lc->half[dir].htlc_min = htlc_min;
	lc->half[dir].htlc_max = htlc_max;
	lc->half[dir].base_fee = base_fee;
	lc->half[dir].proportional_fee = proportional_fee;
	lc->half[dir].delay = delay;

	/* We always add an explicit constraint for local channels, to simplify
	 * lookups.  You can tell it's a fake one by the timestamp. */
	scidd.scid = scid;
	scidd.dir = dir;
	layer_update_constraint(layer, &scidd, CONSTRAINT_MAX, UINT64_MAX, capacity);
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

static struct constraint *layer_find_constraint_nonconst(const struct layer *layer,
							 const struct short_channel_id_dir *scidd,
							 enum constraint_type type)
{
	struct constraint_key k = { *scidd, type };
	return constraint_hash_get(layer->constraints, &k);
}

/* Public one returns const */
const struct constraint *layer_find_constraint(const struct layer *layer,
					       const struct short_channel_id_dir *scidd,
					       enum constraint_type type)
{
	return layer_find_constraint_nonconst(layer, scidd, type);
}

const struct constraint *layer_update_constraint(struct layer *layer,
						 const struct short_channel_id_dir *scidd,
						 enum constraint_type type,
						 u64 timestamp,
						 struct amount_msat limit)
{
	struct constraint *c = layer_find_constraint_nonconst(layer, scidd, type);
	if (!c) {
		c = tal(layer, struct constraint);
		c->key.scidd = *scidd;
		c->key.type = type;
		c->limit = limit;
		constraint_hash_add(layer->constraints, c);
	} else {
		switch (type) {
		case CONSTRAINT_MIN:
			/* Increase minimum? */
			if (amount_msat_greater(limit, c->limit))
				c->limit = limit;
			break;
		case CONSTRAINT_MAX:
			/* Decrease maximum? */
			if (amount_msat_less(limit, c->limit))
				c->limit = limit;
			break;
		}
	}
	c->timestamp = timestamp;
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
		struct gossmap_chan *c = gossmap_find_chan(gossmap, &con->key.scidd.scid);
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
	struct route_exclusion ex;
	ex.type = EXCLUDE_NODE;
	ex.u.node_id = *node;
	tal_arr_expand(&layer->disabled, ex);
}

void layer_add_disabled_channel(struct layer *layer,
				const struct short_channel_id_dir *scidd)
{
	struct route_exclusion ex;
	ex.type = EXCLUDE_CHANNEL;
	ex.u.chan_id = *scidd;
	tal_arr_expand(&layer->disabled, ex);
}

void layer_add_localmods(const struct layer *layer,
			 const struct gossmap *gossmap,
			 bool zero_cost,
			 struct gossmap_localmods *localmods)
{
	const struct local_channel *lc;
	struct local_channel_hash_iter lcit;

	/* First, disable all channels into blocked nodes (local updates
	 * can add new ones)! */
	for (size_t i = 0; i < tal_count(layer->disabled); i++) {
		struct route_exclusion ex = layer->disabled[i];

		/* Disable all channels of excluded nodes. */
		if (ex.type == EXCLUDE_NODE) {
			const struct gossmap_node *node;

			node = gossmap_find_node(gossmap, &ex.u.node_id);
			if (!node)
				continue;
			for (size_t n = 0; n < node->num_chans; n++) {
				struct short_channel_id scid;
				struct gossmap_chan *c;
				int dir;
				c = gossmap_nth_chan(gossmap, node, n, &dir);
				scid = gossmap_chan_scid(gossmap, c);

				/* Disabled zero-capacity on incoming */
				gossmap_local_updatechan(
				    localmods, scid, AMOUNT_MSAT(0),
				    AMOUNT_MSAT(0), 0, 0, 0, false, !dir);
			}
		} else {
			gossmap_local_updatechan(
			    localmods, ex.u.chan_id.scid, AMOUNT_MSAT(0),
			    AMOUNT_MSAT(0), 0, 0, 0, false, ex.u.chan_id.dir);
		}
	}

	for (lc = local_channel_hash_first(layer->local_channels, &lcit);
	     lc;
	     lc = local_channel_hash_next(layer->local_channels, &lcit)) {
		gossmap_local_addchan(localmods,
				      &lc->n1, &lc->n2, lc->scid, NULL);
		for (size_t i = 0; i < ARRAY_SIZE(lc->half); i++) {
			u64 base, propfee, delay;
			if (!lc->half[i].enabled)
				continue;
			if (zero_cost) {
				base = propfee = delay = 0;
			} else {
				base = lc->half[i].base_fee.millisatoshis; /* Raw: gossmap */
				propfee = lc->half[i].proportional_fee;
				delay = lc->half[i].delay;
			}
			gossmap_local_updatechan(localmods, lc->scid,
						 lc->half[i].htlc_min,
						 lc->half[i].htlc_max,
						 base, propfee, delay,
						 true,
						 i);
		}
	}
}

static void json_add_local_channel(struct json_stream *response,
				   const char *fieldname,
				   const struct local_channel *lc,
				   int dir)
{
	json_object_start(response, fieldname);

	if (dir == 0) {
		json_add_node_id(response, "source", &lc->n1);
		json_add_node_id(response, "destination", &lc->n2);
	} else {
		json_add_node_id(response, "source", &lc->n2);
		json_add_node_id(response, "destination", &lc->n1);
	}
	json_add_short_channel_id(response, "short_channel_id", lc->scid);
	json_add_amount_msat(response, "capacity_msat", lc->capacity);
	json_add_amount_msat(response, "htlc_minimum_msat", lc->half[dir].htlc_min);
	json_add_amount_msat(response, "htlc_maximum_msat", lc->half[dir].htlc_max);
	json_add_amount_msat(response, "fee_base_msat", lc->half[dir].base_fee);
	json_add_u32(response, "fee_proportional_millionths", lc->half[dir].proportional_fee);
	json_add_u32(response, "delay", lc->half[dir].delay);

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
	json_add_short_channel_id(js, "short_channel_id", c->key.scidd.scid);
	json_add_u32(js, "direction", c->key.scidd.dir);
	json_add_u64(js, "timestamp", c->timestamp);
	switch (c->key.type) {
	case CONSTRAINT_MIN:
		json_add_amount_msat(js, "minimum_msat", c->limit);
		break;
	case CONSTRAINT_MAX:
		json_add_amount_msat(js, "maximum_msat", c->limit);
		break;
	}
	json_object_end(js);
}

static void json_add_layer(struct json_stream *js,
			   const char *fieldname,
			   const struct layer *layer)
{
	struct local_channel_hash_iter lcit;
	const struct local_channel *lc;
	struct constraint_hash_iter conit;
	const struct constraint *c;

	json_object_start(js, fieldname);
	json_add_string(js, "layer", layer->name);
	json_array_start(js, "disabled");
	for (size_t i = 0; i < tal_count(layer->disabled); i++)
		json_add_route_exclusion(js, NULL, &layer->disabled[i]);
	json_array_end(js);
	json_array_start(js, "created_channels");
	for (lc = local_channel_hash_first(layer->local_channels, &lcit);
	     lc;
	     lc = local_channel_hash_next(layer->local_channels, &lcit)) {
		for (size_t i = 0; i < ARRAY_SIZE(lc->half); i++) {
			if (lc->half[i].enabled)
				json_add_local_channel(js, NULL, lc, i);
		}
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
		     const char *layername)
{
	struct layer *l;

	json_array_start(js, fieldname);
	list_for_each(&askrene->layers, l, list) {
		if (layername && !streq(l->name, layername))
			continue;
		json_add_layer(js, NULL, l);
	}
	json_array_end(js);
}

void layer_memleak_mark(struct askrene *askrene, struct htable *memtable)
{
	struct layer *l;
	list_for_each(&askrene->layers, l, list) {
		memleak_scan_htable(memtable, &l->constraints->raw);
		memleak_scan_htable(memtable, &l->local_channels->raw);
	}
}
