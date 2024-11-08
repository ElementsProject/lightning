#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/layer.h>
#include <wire/wire.h>

/* Different elements in the datastore */
enum dstore_layer_type {
	/* We don't use type 0, which fromwire_u16 returns on trunction */
	DSTORE_CHANNEL = 1,
	DSTORE_CHANNEL_UPDATE = 2,
	DSTORE_CHANNEL_CONSTRAINT = 3,
	DSTORE_CHANNEL_BIAS = 4,
	DSTORE_DISABLED_NODE = 5,
};

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

/* A bias, for special-effects (user-controlled) */
struct bias {
	struct short_channel_id_dir scidd;
	const char *description;
	s8 bias;
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

static const struct short_channel_id_dir *
bias_scidd(const struct bias *bias)
{
	return &bias->scidd;
}

static bool bias_eq_scidd(const struct bias *bias,
			  const struct short_channel_id_dir *scidd)
{
	return short_channel_id_dir_eq(scidd, &bias->scidd);
}

HTABLE_DEFINE_TYPE(struct bias, bias_scidd, hash_scidd,
		   bias_eq_scidd, bias_hash);

struct layer {
	/* Inside global list of layers */
	struct list_node list;

	/* Convenience pointer to askrene */
	struct askrene *askrene;

	/* Unique identifiers */
	const char *name;

	/* Save to datastore */
	bool persistent;

	/* Completely made up local additions, indexed by scid */
	struct local_channel_hash *local_channels;

	/* Modifications to channels, indexed by scidd */
	struct local_update_hash *local_updates;

	/* Additional info, indexed by scid+dir */
	struct constraint_hash *constraints;

	/* Bias, indexed by scid+dir */
	struct bias_hash *biases;

	/* Nodes to completely disable (tal_arr) */
	struct node_id *disabled_nodes;
};

struct layer *new_temp_layer(const tal_t *ctx, struct askrene *askrene, const char *name TAKES)
{
	struct layer *l = tal(ctx, struct layer);

	l->askrene = askrene;
	l->name = tal_strdup(l, name);
	l->persistent = false;
	l->local_channels = tal(l, struct local_channel_hash);
	local_channel_hash_init(l->local_channels);
	l->local_updates = tal(l, struct local_update_hash);
	local_update_hash_init(l->local_updates);
	l->constraints = tal(l, struct constraint_hash);
	constraint_hash_init(l->constraints);
	l->biases = tal(l, struct bias_hash);
	bias_hash_init(l->biases);
	l->disabled_nodes = tal_arr(l, struct node_id, 0);

	return l;
}

static void destroy_layer(struct layer *l, struct askrene *askrene)
{
	list_del_from(&askrene->layers, &l->list);
}

static struct command_result *ignore_result(struct command *aux_cmd,
					    const char *method,
					    const char *buf,
					    const jsmntok_t *result,
					    void *arg)
{
	return command_still_pending(aux_cmd);
}

static void json_add_layer_key(struct json_stream *js,
			       const char *fieldname,
			       const struct layer *layer)
{
	json_array_start(js, fieldname);
	json_add_string(js, NULL, "askrene");
	json_add_string(js, NULL, "layers");
	json_add_string(js, NULL, layer->name);
	json_array_end(js);
}

static void save_remove(struct layer *layer)
{
	struct out_req *req;

	if (!layer->persistent)
		return;

	req = jsonrpc_request_start(layer->askrene->layer_cmd,
				    "deldatastore",
				    ignore_result,
				    plugin_broken_cb,
				    NULL);
	json_add_layer_key(req->js, "key", layer);
	send_outreq(req);
}

static void append_layer_datastore(struct layer *layer, const u8 *data)
{
	struct out_req *req = jsonrpc_request_start(layer->askrene->layer_cmd,
						    "datastore",
						    ignore_result,
						    plugin_broken_cb,
						    NULL);
	json_add_layer_key(req->js, "key", layer);
	json_add_hex_talarr(req->js, "hex", data);
	json_add_string(req->js, "mode", "create-or-append");
	send_outreq(req);
}

/* We don't autogenerate our wire code here.  Partially because the
 * fromwire_ routines we generate are aimed towards single messages,
 * not a continuous stream, but also because this needs to be
 * consistent across updates, and the extensions to the wire format
 * we use (for inter-daemon comms) do not have such a guarantee */

/* Helper to append bool to data, and return value */
static bool towire_bool_val(u8 **pptr, bool v)
{
	towire_bool(pptr, v);
	return v;
}

static void towire_short_channel_id_dir(u8 **pptr, const struct short_channel_id_dir *scidd)
{
	towire_short_channel_id(pptr, scidd->scid);
	towire_u8(pptr, scidd->dir);
}

static void fromwire_short_channel_id_dir(const u8 **cursor, size_t *max,
					  struct short_channel_id_dir *scidd)
{
	scidd->scid = fromwire_short_channel_id(cursor, max);
	scidd->dir = fromwire_u8(cursor, max);
}

static void towire_save_channel(u8 **data, const struct local_channel *lc)
{
	towire_u16(data, DSTORE_CHANNEL);
	towire_node_id(data, &lc->n1);
	towire_node_id(data, &lc->n2);
	towire_short_channel_id(data, lc->scid);
	towire_amount_msat(data, lc->capacity);
}

static void save_channel(struct layer *layer, const struct local_channel *lc)
{
	u8 *data;

	if (!layer->persistent)
		return;

	data = tal_arr(tmpctx, u8, 0);
	towire_save_channel(&data, lc);
	append_layer_datastore(layer, data);
}

static void load_channel(struct plugin *plugin,
			 struct layer *layer,
			 const u8 **cursor,
			 size_t *len)
{
	struct node_id n1, n2;
	struct short_channel_id scid;
	struct amount_msat capacity;

	fromwire_node_id(cursor, len, &n1);
	fromwire_node_id(cursor, len, &n2);
	scid = fromwire_short_channel_id(cursor, len);
	capacity = fromwire_amount_msat(cursor, len);

	if (*cursor)
		layer_add_local_channel(layer, &n1, &n2, scid, capacity);
}

static void towire_save_channel_update(u8 **data, const struct local_update *lu)
{
	towire_u16(data, DSTORE_CHANNEL_UPDATE);
	towire_short_channel_id_dir(data, &lu->scidd);
	if (towire_bool_val(data, lu->enabled != NULL))
		towire_bool(data, *lu->enabled);
	if (towire_bool_val(data, lu->htlc_min != NULL))
		towire_amount_msat(data, *lu->htlc_min);
	if (towire_bool_val(data, lu->htlc_max != NULL))
		towire_amount_msat(data, *lu->htlc_max);
	if (towire_bool_val(data, lu->base_fee != NULL))
		towire_amount_msat(data, *lu->base_fee);
	if (towire_bool_val(data, lu->proportional_fee != NULL))
		towire_u32(data, *lu->proportional_fee);
	if (towire_bool_val(data, lu->delay != NULL))
		towire_u16(data, *lu->delay);
}

static void save_channel_update(struct layer *layer, const struct local_update *lu)
{
	u8 *data;

	if (!layer->persistent)
		return;

	data = tal_arr(tmpctx, u8, 0);
	towire_save_channel_update(&data, lu);
	append_layer_datastore(layer, data);
}

static void load_channel_update(struct plugin *plugin,
				struct layer *layer,
				const u8 **cursor,
				size_t *len)
{
	struct short_channel_id_dir scidd;
	bool *enabled = NULL, enabled_val;
	struct amount_msat *htlc_min = NULL, htlc_min_val;
	struct amount_msat *htlc_max = NULL, htlc_max_val;
	struct amount_msat *base_fee = NULL, base_fee_val;
	u32 *proportional_fee = NULL, proportional_fee_val;
	u16 *delay = NULL, delay_val;

	fromwire_short_channel_id_dir(cursor, len, &scidd);
	if (fromwire_bool(cursor, len)) {
		enabled_val = fromwire_bool(cursor, len);
		enabled = &enabled_val;
	}
	if (fromwire_bool(cursor, len)) {
		htlc_min_val = fromwire_amount_msat(cursor, len);
		htlc_min = &htlc_min_val;
	}
	if (fromwire_bool(cursor, len)) {
		htlc_max_val = fromwire_amount_msat(cursor, len);
		htlc_max = &htlc_max_val;
	}
	if (fromwire_bool(cursor, len)) {
		base_fee_val = fromwire_amount_msat(cursor, len);
		base_fee = &base_fee_val;
	}
	if (fromwire_bool(cursor, len)) {
		proportional_fee_val = fromwire_u32(cursor, len);
		proportional_fee = &proportional_fee_val;
	}
	if (fromwire_bool(cursor, len)) {
		delay_val = fromwire_u16(cursor, len);
		delay = &delay_val;
	}

	if (*cursor)
		layer_add_update_channel(layer, &scidd,
					 enabled,
					 htlc_min,
					 htlc_max,
					 base_fee,
					 proportional_fee,
					 delay);
}

static void towire_save_channel_constraint(u8 **data, const struct constraint *c)
{
	towire_u16(data, DSTORE_CHANNEL_CONSTRAINT);
	towire_short_channel_id_dir(data, &c->scidd);
	towire_u64(data, c->timestamp);
	if (towire_bool_val(data, !amount_msat_is_zero(c->min)))
		towire_amount_msat(data, c->min);
	if (towire_bool_val(data, !amount_msat_eq(c->max, AMOUNT_MSAT(UINT64_MAX))))
		towire_amount_msat(data, c->max);
}

static void save_channel_constraint(struct layer *layer, const struct constraint *c)
{
	u8 *data;

	if (!layer->persistent)
		return;

	data = tal_arr(tmpctx, u8, 0);
	towire_save_channel_constraint(&data, c);
	append_layer_datastore(layer, data);
}

static void load_channel_constraint(struct plugin *plugin,
				    struct layer *layer,
				    const u8 **cursor,
				    size_t *len)
{
	struct short_channel_id_dir scidd;
	struct amount_msat *min = NULL, min_val;
	struct amount_msat *max = NULL, max_val;
	u64 timestamp;

	fromwire_short_channel_id_dir(cursor, len, &scidd);
	timestamp = fromwire_u64(cursor, len);
	if (fromwire_bool(cursor, len)) {
		min_val = fromwire_amount_msat(cursor, len);
		min = &min_val;
	}
	if (fromwire_bool(cursor, len)) {
		max_val = fromwire_amount_msat(cursor, len);
		max = &max_val;
	}
	if (*cursor)
		layer_add_constraint(layer, &scidd, timestamp, min, max);
}

static void towire_save_channel_bias(u8 **data, const struct bias *bias)
{
	towire_u16(data, DSTORE_CHANNEL_BIAS);
	towire_short_channel_id_dir(data, &bias->scidd);
	towire_s8(data, bias->bias);
	towire_wirestring(data, bias->description);
}

static void save_channel_bias(struct layer *layer, const struct bias *bias)
{
	u8 *data;

	if (!layer->persistent)
		return;

	data = tal_arr(tmpctx, u8, 0);
	towire_save_channel_bias(&data, bias);
	append_layer_datastore(layer, data);
}

static void load_channel_bias(struct plugin *plugin,
			      struct layer *layer,
			      const u8 **cursor,
			      size_t *len)
{
	struct short_channel_id_dir scidd;
	char *description;
	s8 bias_factor;

	fromwire_short_channel_id_dir(cursor, len, &scidd);
	bias_factor = fromwire_s8(cursor, len);
	description = fromwire_wirestring(tmpctx, cursor, len);

	if (*cursor)
		layer_set_bias(layer, &scidd, take(description), bias_factor);
}

static void towire_save_disabled_node(u8 **data, const struct node_id *node)
{
	towire_u16(data, DSTORE_DISABLED_NODE);
	towire_node_id(data, node);
}

static void save_disabled_node(struct layer *layer, const struct node_id *node)
{
	u8 *data;

	if (!layer->persistent)
		return;
	data = tal_arr(tmpctx, u8, 0);
	towire_save_disabled_node(&data, node);
	append_layer_datastore(layer, data);
}

static void load_disabled_node(struct plugin *plugin,
			       struct layer *layer,
			       const u8 **cursor,
			       size_t *len)
{
	struct node_id node;

	fromwire_node_id(cursor, len, &node);
	if (*cursor)
		layer_add_disabled_node(layer, &node);
}

static void save_complete_layer(struct layer *layer)
{
	struct local_channel_hash_iter lcit;
	const struct local_channel *lc;
	const struct local_update *lu;
	struct local_update_hash_iter luit;
	struct constraint_hash_iter conit;
	const struct constraint *c;
	struct bias_hash_iter biasit;
	const struct bias *b;
	struct out_req *req;
	u8 *data;

	if (!layer->persistent)
		return;

	data = tal_arr(tmpctx, u8, 0);
	for (size_t i = 0; i < tal_count(layer->disabled_nodes); i++)
		towire_save_disabled_node(&data, &layer->disabled_nodes[i]);

	for (lc = local_channel_hash_first(layer->local_channels, &lcit);
	     lc;
	     lc = local_channel_hash_next(layer->local_channels, &lcit)) {
		towire_save_channel(&data, lc);
	}
	for (lu = local_update_hash_first(layer->local_updates, &luit);
	     lu;
	     lu = local_update_hash_next(layer->local_updates, &luit)) {
		towire_save_channel_update(&data, lu);
	}
	for (c = constraint_hash_first(layer->constraints, &conit);
	     c;
	     c = constraint_hash_next(layer->constraints, &conit)) {
		/* Don't save ones we generated internally */
		if (c->timestamp == UINT64_MAX)
			continue;
		towire_save_channel_constraint(&data, c);
	}
	for (b = bias_hash_first(layer->biases, &biasit);
	     b;
	     b = bias_hash_next(layer->biases, &biasit)) {
		towire_save_channel_bias(&data, b);
	}

	/* Wholesale replacement */
	req = jsonrpc_request_start(layer->askrene->layer_cmd,
				    "datastore",
				    ignore_result,
				    plugin_broken_cb,
				    NULL);
	json_add_layer_key(req->js, "key", layer);
	json_add_hex_talarr(req->js, "hex", data);
	json_add_string(req->js, "mode", "create-or-replace");
	send_outreq(req);
}

void save_new_layer(struct layer *layer)
{
	return save_complete_layer(layer);
}

static void populate_layer(struct askrene *askrene,
			   const char *layername TAKES,
			   const u8 *data)
{
	struct layer *layer = new_layer(askrene, layername, true);
	size_t len = tal_bytelen(data);

	plugin_log(askrene->plugin, LOG_DBG,
		   "Loaded level %s (%zu bytes)",
		   layer->name, len);

	while (len != 0) {
		enum dstore_layer_type type;
		type = fromwire_u16(&data, &len);

		switch (type) {
		case DSTORE_CHANNEL:
			load_channel(askrene->plugin, layer, &data, &len);
			continue;
		case DSTORE_CHANNEL_UPDATE:
			load_channel_update(askrene->plugin, layer, &data, &len);
			continue;
		case DSTORE_CHANNEL_CONSTRAINT:
			load_channel_constraint(askrene->plugin, layer, &data, &len);
			continue;
		case DSTORE_CHANNEL_BIAS:
			load_channel_bias(askrene->plugin, layer, &data, &len);
			continue;
		case DSTORE_DISABLED_NODE:
			load_disabled_node(askrene->plugin, layer, &data, &len);
			continue;
		}
		plugin_err(askrene->plugin, "Invalid type %i in datastore: layer %s %s",
			   type, layer->name, tal_hexstr(tmpctx, data, len));
	}
	if (!data)
		plugin_log(askrene->plugin, LOG_BROKEN,
			   "%s: invalid data in datastore",
			   layer->name);
}

static struct command_result *listdatastore_done(struct command *aux_cmd,
						 const char *method,
						 const char *buf,
						 const jsmntok_t *result,
						 struct askrene *askrene)
{
	const jsmntok_t *datastore, *t, *key, *data;
	size_t i;

	plugin_log(aux_cmd->plugin, LOG_DBG, "datastore = %.*s",
		   json_tok_full_len(result),
		   json_tok_full(buf, result));
	datastore = json_get_member(buf, result, "datastore");
	json_for_each_arr(i, t, datastore) {
		const char *layername;

		/* Key is an array, first two elements are askrene, layers */
		key = json_get_member(buf, t, "key") + 3;
		data = json_get_member(buf, t, "hex");
		/* In case someone creates a subdir? */
		if (!data)
			continue;
		layername = json_strdup(NULL, buf, key);
		populate_layer(askrene,
			       take(layername),
			       json_tok_bin_from_hex(tmpctx, buf, data));
	}
	return command_still_pending(aux_cmd);
}

void load_layers(struct askrene *askrene)
{
	struct out_req *req = jsonrpc_request_start(askrene->layer_cmd,
						    "listdatastore",
						    listdatastore_done,
						    plugin_broken_cb,
						    askrene);
	json_array_start(req->js, "key");
	json_add_string(req->js, NULL, "askrene");
	json_add_string(req->js, NULL, "layers");
	json_array_end(req->js);
	send_outreq(req);
}

void remove_layer(struct layer *l)
{
	save_remove(l);
	tal_free(l);
}

struct layer *new_layer(struct askrene *askrene, const char *name TAKES, bool persistent)
{
	struct layer *l = new_temp_layer(askrene, askrene, name);
	l->persistent = persistent;
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
	save_channel(layer, lc);
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
	save_channel_update(layer, lu);
}

const struct bias *layer_set_bias(struct layer *layer,
				  const struct short_channel_id_dir *scidd,
				  const char *description TAKES,
				  s8 bias_factor)
{
	struct bias *bias;

	bias = bias_hash_get(layer->biases, scidd);
	if (!bias) {
		bias = tal(layer, struct bias);
		bias->scidd = *scidd;
		bias_hash_add(layer->biases, bias);
	} else {
		tal_free(bias->description);
	}

	bias->bias = bias_factor;
	bias->description = tal_strdup_or_null(bias, description);

	save_channel_bias(layer, bias);

	/* Don't bother keeping around zero biases */
	if (bias_factor == 0) {
		bias_hash_del(layer->biases, bias);
		bias = tal_free(bias);
	}
	return bias;
}

void layer_apply_biases(const struct layer *layer,
			const struct gossmap *gossmap,
			s8 *biases)
{
	struct bias *bias;
	struct bias_hash_iter it;

	for (bias = bias_hash_first(layer->biases, &it);
	     bias;
	     bias = bias_hash_next(layer->biases, &it)) {
		struct gossmap_chan *c;

		c = gossmap_find_chan(gossmap, &bias->scidd.scid);
		if (!c)
			continue;
		biases[(gossmap_chan_idx(gossmap, c) << 1) | bias->scidd.dir]
			= bias->bias;
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
		*min = amount_msat_max(*min, c->min);
		*max = amount_msat_min(*max, c->max);
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
	save_channel_constraint(layer, c);
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

	save_complete_layer(layer);
	return num_removed;
}

void layer_add_disabled_node(struct layer *layer, const struct node_id *node)
{
	tal_arr_expand(&layer->disabled_nodes, *node);
	save_disabled_node(layer, node);
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
			c = gossmap_nth_chan(gossmap, node, n, &scidd.dir);
			scidd.scid = gossmap_chan_scid(gossmap, c);

			/* Disabled zero-capacity on incoming */
			gossmap_local_updatechan(localmods,
						 &scidd,
						 &enabled,
						 NULL, NULL, NULL, NULL, NULL);
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

void json_add_bias(struct json_stream *js,
		   const char *fieldname,
		   const struct bias *b,
		   const struct layer *layer)
{
	json_object_start(js, fieldname);
	if (layer)
		json_add_string(js, "layer", layer->name);
	json_add_short_channel_id_dir(js, "short_channel_id_dir", b->scidd);
	if (b->description)
		json_add_string(js, "description", b->description);
	json_add_s64(js, "bias", b->bias);
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
	struct bias_hash_iter biasit;
	const struct bias *b;

	json_object_start(js, fieldname);
	json_add_string(js, "layer", layer->name);
	json_add_bool(js, "persistent", layer->persistent);
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
	json_array_start(js, "biases");
	for (b = bias_hash_first(layer->biases, &biasit);
	     b;
	     b = bias_hash_next(layer->biases, &biasit)) {
		json_add_bias(js, NULL, b, NULL);
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

bool layer_disables_chan(const struct layer *layer,
			 const struct short_channel_id_dir *scidd)
{
	const struct local_update *lu;

	lu = local_update_hash_get(layer->local_updates, scidd);

	return (lu && lu->enabled && *lu->enabled == false);
}

bool layer_disables_node(const struct layer *layer,
			 const struct node_id *node)
{
	for (size_t i = 0; i < tal_count(layer->disabled_nodes); i++) {
		if (node_id_eq(&layer->disabled_nodes[i], node))
			return true;
	}
	return false;
}

void layer_memleak_mark(struct askrene *askrene, struct htable *memtable)
{
	struct layer *l;
	list_for_each(&askrene->layers, l, list) {
		memleak_scan_htable(memtable, &l->constraints->raw);
		memleak_scan_htable(memtable, &l->local_channels->raw);
		memleak_scan_htable(memtable, &l->local_updates->raw);
		memleak_scan_htable(memtable, &l->biases->raw);
	}
}
