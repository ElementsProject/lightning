#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/clock_time.h>
#include <common/gossmap.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/datastore_wire.h>
#include <plugins/askrene/layer.h>
#include <wire/wire.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

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
	u64 timestamp;
};

struct node_bias {
	struct node_id node;
	const char *description;
	s8 in_bias, out_bias;
	u64 timestamp;
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

HTABLE_DEFINE_DUPS_TYPE(struct constraint, constraint_scidd, hash_scidd,
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

HTABLE_DEFINE_NODUPS_TYPE(struct local_channel, local_channel_scid, hash_scid,
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

HTABLE_DEFINE_NODUPS_TYPE(struct local_update, local_update_scidd, hash_scidd,
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

HTABLE_DEFINE_NODUPS_TYPE(struct bias, bias_scidd, hash_scidd,
			  bias_eq_scidd, bias_hash);

static const struct node_id *bias_nodeid(const struct node_bias *bias)
{
	return &bias->node;
}

static size_t hash_nodeid(const struct node_id *node)
{
	return *(size_t *)(node->k);
}

static bool bias_eq_nodeid(const struct node_bias *bias,
			   const struct node_id *node)
{
	return node_id_eq(node, &bias->node);
}

HTABLE_DEFINE_NODUPS_TYPE(struct node_bias, bias_nodeid, hash_nodeid,
			  bias_eq_nodeid, node_bias_hash);

struct layer {
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

	/* Node bias, indexed by node_id */
	struct node_bias_hash *node_biases;

	/* Nodes to completely disable (tal_arr) */
	struct node_id *disabled_nodes;
};

static size_t hash_str(const char *str)
{
	return siphash24(siphash_seed(), str, strlen(str));
}

static bool layer_eq_name(const struct layer *l,
			  const char *name)
{
	return streq(l->name, name);
}

HTABLE_DEFINE_NODUPS_TYPE(struct layer, layer_name, hash_str,
			  layer_eq_name, layer_name_hash);

struct layer_name_hash *new_layer_name_hash(const tal_t *ctx)
{
	return new_htable(ctx, layer_name_hash);
}

struct layer *new_temp_layer(const tal_t *ctx, struct askrene *askrene, const char *name TAKES)
{
	struct layer *l = tal(ctx, struct layer);

	l->askrene = askrene;
	l->name = tal_strdup(l, name);
	l->persistent = false;
	l->local_channels = new_htable(l, local_channel_hash);
	l->local_updates = new_htable(l, local_update_hash);
	l->constraints = new_htable(l, constraint_hash);
	l->biases = new_htable(l, bias_hash);
	l->node_biases = new_htable(l, node_bias_hash);
	l->disabled_nodes = tal_arr(l, struct node_id, 0);

	return l;
}

static void destroy_layer(struct layer *l, struct askrene *askrene)
{
	if (!layer_name_hash_del(askrene->layers, l))
		abort();
}

/* Low-level versions of routines which do *not* save (used for loading, too) */
static struct layer *add_layer(struct askrene *askrene, const char *name TAKES, bool persistent)
{
	struct layer *l = new_temp_layer(askrene, askrene, name);
	l->persistent = persistent;
	assert(!find_layer(askrene, l->name));
	layer_name_hash_add(askrene->layers, l);
	tal_add_destructor2(l, destroy_layer, askrene);
	return l;
}

static struct local_channel *add_local_channel(struct layer *layer,
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

static struct local_update *add_update_channel(struct layer *layer,
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
	return lu;
}

static const struct constraint *add_constraint(struct layer *layer,
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

static const struct bias *set_bias(struct layer *layer,
				   const struct short_channel_id_dir *scidd,
				   const char *description TAKES,
				   s8 bias_factor,
				   bool relative,
				   u64 timestamp)
{
	struct bias *bias;

	bias = bias_hash_get(layer->biases, scidd);
	if (!bias) {
		bias = tal(layer, struct bias);
		bias->scidd = *scidd;
		bias_hash_add(layer->biases, bias);
		bias->bias = 0;
	} else {
		tal_free(bias->description);
	}
	int bias_new = relative ? bias->bias + bias_factor : bias_factor;
	bias_new = MIN(100, bias_new);
	bias_new = MAX(-100, bias_new);
	bias->bias = bias_new;
	bias->description = tal_strdup_or_null(bias, description);
	bias->timestamp = timestamp;

	/* Don't bother keeping around zero biases */
	if (bias->bias == 0) {
		bias_hash_del(layer->biases, bias);
		bias = tal_free(bias);
	}
	return bias;
}

static const struct node_bias *set_node_bias(struct layer *layer,
					     const struct node_id *node,
					     const char *description TAKES,
					     s8 bias_factor,
					     bool relative,
					     bool dir_out,
					     u64 timestamp)
{
	struct node_bias *bias;

	bias = node_bias_hash_get(layer->node_biases, node);
	if (!bias) {
		bias = tal(layer, struct node_bias);
		bias->node = *node;
		node_bias_hash_add(layer->node_biases, bias);
		bias->in_bias = 0;
		bias->out_bias = 0;
	} else {
		tal_free(bias->description);
	}
	bias->description = tal_strdup_or_null(bias, description);
	bias->timestamp = timestamp;

	if (dir_out) {
		int bias_new =
		    relative ? bias->out_bias + bias_factor : bias_factor;
		bias_new = MIN(100, bias_new);
		bias_new = MAX(-100, bias_new);
		bias->out_bias = bias_new;
	} else {
		int bias_new =
		    relative ? bias->in_bias + bias_factor : bias_factor;
		bias_new = MIN(100, bias_new);
		bias_new = MAX(-100, bias_new);
		bias->in_bias = bias_new;
	}

	/* Don't bother keeping around zero biases */
	if (bias->in_bias == 0 && bias->out_bias == 0) {
		node_bias_hash_del(layer->node_biases, bias);
		bias = tal_free(bias);
	}
	return bias;
}

static void add_disabled_node(struct layer *layer, const struct node_id *node)
{
	tal_arr_expand(&layer->disabled_nodes, *node);
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

static void towire_save_channel(u8 **data, const struct local_channel *lc)
{
	towire_dstore_channel(data, &lc->n1, &lc->n2, lc->scid, lc->capacity);
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

	if (fromwire_dstore_channel(cursor, len, &n1, &n2, &scid, &capacity))
		add_local_channel(layer, &n1, &n2, scid, capacity);
}

static void towire_save_channel_update(u8 **data, const struct local_update *lu)
{
	towire_dstore_channel_update(data,
				     &lu->scidd,
				     lu->enabled,
				     lu->htlc_min,
				     lu->htlc_max,
				     lu->base_fee,
				     lu->proportional_fee,
				     lu->delay);
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
	bool *enabled;
	struct amount_msat *htlc_min, *htlc_max, *base_fee;
	u32 *proportional_fee;
	u16 *delay;

	if (fromwire_dstore_channel_update(tmpctx, cursor, len,
					   &scidd,
					   &enabled,
					   &htlc_min,
					   &htlc_max,
					   &base_fee,
					   &proportional_fee,
					   &delay))
		add_update_channel(layer, &scidd,
				   enabled,
				   htlc_min,
				   htlc_max,
				   base_fee,
				   proportional_fee,
				   delay);
}

static void towire_save_channel_constraint(u8 **data, const struct constraint *c)
{
	towire_dstore_channel_constraint(data, &c->scidd, c->timestamp,
					 amount_msat_is_zero(c->min) ? NULL : &c->min,
					 amount_msat_eq(c->max, AMOUNT_MSAT(UINT64_MAX)) ? NULL: &c->max);
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
	struct amount_msat *min;
	struct amount_msat *max;
	u64 timestamp;

	if (fromwire_dstore_channel_constraint(tmpctx, cursor, len,
					       &scidd, &timestamp,
					       &min, &max))
		add_constraint(layer, &scidd, timestamp, min, max);
}

static void towire_save_channel_bias(u8 **data, const struct bias *bias)
{
	towire_dstore_channel_bias_v2(data,
				      &bias->scidd,
				      bias->bias,
				      bias->description,
				      bias->timestamp);
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

static void towire_save_node_bias(u8 **data, const struct node_bias *bias)
{
	towire_dstore_node_bias(data,
				&bias->node,
				bias->description,
				bias->in_bias,
				bias->out_bias,
				bias->timestamp);
}

static void save_node_bias(struct layer *layer, const struct node_bias *bias)
{
	u8 *data;

	if (!layer->persistent)
		return;

	data = tal_arr(tmpctx, u8, 0);
	towire_save_node_bias(&data, bias);
	append_layer_datastore(layer, data);
}

static void load_channel_bias(struct plugin *plugin,
			      struct layer *layer,
			      const u8 **cursor,
			      size_t *len)
{
	struct short_channel_id_dir scidd;
	const char *description;
	s8 bias_factor;
        /* If we read an old version without timestamp, just put the current
         * time. */
        u64 timestamp = clock_time().ts.tv_sec;

	if (fromwire_dstore_channel_bias(tmpctx, cursor, len,
					 &scidd,
					 &bias_factor,
					 &description))
		set_bias(layer, &scidd, take(description), bias_factor, false,
			 timestamp);
}

static void load_channel_bias_v2(struct plugin *plugin,
                                 struct layer *layer,
                                 const u8 **cursor,
                                 size_t *len)
{
	struct short_channel_id_dir scidd;
	const char *description;
	s8 bias_factor;
	u64 timestamp;

	if (fromwire_dstore_channel_bias_v2(tmpctx, cursor, len,
					    &scidd,
					    &bias_factor,
					    &description,
					    &timestamp))
		set_bias(layer, &scidd, take(description), bias_factor, false,
			 timestamp);
}

static void load_node_bias(struct plugin *plugin,
			   struct layer *layer,
			   const u8 **cursor,
			   size_t *len)
{
	struct node_id node;
	const char *description;
	s8 in_bias, out_bias;
	u64 timestamp;

	if (fromwire_dstore_node_bias(tmpctx, cursor, len,
				      &node,
				      &description,
				      &in_bias,
				      &out_bias,
				      &timestamp)) {
		set_node_bias(layer, &node, take(description), in_bias,
			      /* relative = */ false,
			      /* out dir = */ false, timestamp);
		set_node_bias(layer, &node, take(description), out_bias,
			      /* relative = */ false,
			      /* out dir = */ true, timestamp);
	}
}

static void save_disabled_node(struct layer *layer, const struct node_id *node)
{
	u8 *data;

	if (!layer->persistent)
		return;
	data = tal_arr(tmpctx, u8, 0);
	towire_dstore_disabled_node(&data, node);
	append_layer_datastore(layer, data);
}

static void load_disabled_node(struct plugin *plugin,
			       struct layer *layer,
			       const u8 **cursor,
			       size_t *len)
{
	struct node_id node;

	if (fromwire_dstore_disabled_node(cursor, len, &node))
		add_disabled_node(layer, &node);
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
	struct node_bias_hash_iter nbiasit;
	const struct node_bias *nb;
	struct out_req *req;
	u8 *data;

	if (!layer->persistent)
		return;

	data = tal_arr(tmpctx, u8, 0);
	for (size_t i = 0; i < tal_count(layer->disabled_nodes); i++)
		towire_dstore_disabled_node(&data, &layer->disabled_nodes[i]);

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
	for (nb = node_bias_hash_first(layer->node_biases, &nbiasit); nb;
	     nb = node_bias_hash_next(layer->node_biases, &nbiasit)) {
		towire_save_node_bias(&data, nb);
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

static void populate_layer(struct askrene *askrene,
			   const char *layername TAKES,
			   const u8 *data)
{
	struct layer *layer;
	size_t len = tal_bytelen(data);

	layer = add_layer(askrene, layername, true);
	plugin_log(askrene->plugin, LOG_DBG,
		   "Loaded level %s (%zu bytes)",
		   layer->name, len);

	while (len != 0) {
		enum dstore_layer_type type;
		type = fromwire_peektypen(data, len);

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
		case DSTORE_CHANNEL_BIAS_V2:
			load_channel_bias_v2(askrene->plugin, layer, &data, &len);
			continue;
		case DSTORE_DISABLED_NODE:
			load_disabled_node(askrene->plugin, layer, &data, &len);
			continue;
		case DSTORE_NODE_BIAS:
			load_node_bias(askrene->plugin, layer, &data, &len);
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

void load_layers(struct askrene *askrene, struct command *init_cmd)
{
	struct json_out *params = json_out_new(init_cmd);
	const jsmntok_t *result;
	const char *buf;
	const jsmntok_t *datastore, *t, *key, *data;
	size_t i;


	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "askrene");
	json_out_addstr(params, NULL, "layers");
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(tmpctx, init_cmd,
				      "listdatastore",
				      params, &buf);

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
}

void remove_layer(struct layer *l)
{
	save_remove(l);
	tal_free(l);
}

struct layer *new_layer(struct askrene *askrene,
			const char *name TAKES,
			bool persistent)
{
	struct layer *layer = add_layer(askrene, name, persistent);
	if (persistent)
		save_complete_layer(layer);
	return layer;
}

struct layer *find_layer(struct askrene *askrene, const char *name)
{
	return layer_name_hash_get(askrene->layers, name);
}

const char *layer_name(const struct layer *layer)
{
	return layer->name;
}

void layer_add_local_channel(struct layer *layer,
			     const struct node_id *src,
			     const struct node_id *dst,
			     struct short_channel_id scid,
			     struct amount_msat capacity)
{
	struct local_channel *lc;
	lc = add_local_channel(layer, src, dst, scid, capacity);
	save_channel(layer, lc);
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

	lu = add_update_channel(layer, scidd, enabled,
				htlc_min, htlc_max,
				base_fee, proportional_fee,
				delay);
	save_channel_update(layer, lu);
}

const struct bias *layer_set_bias(struct layer *layer,
				  const struct short_channel_id_dir *scidd,
				  const char *description TAKES,
				  s8 bias_factor,
				  bool relative,
				  u64 timestamp)
{
	const struct bias *bias;

	bias = set_bias(layer, scidd, description, bias_factor, relative,
			timestamp);
	save_channel_bias(layer, bias);
	return bias;
}

const struct node_bias *layer_set_node_bias(struct layer *layer,
					    const struct node_id *node,
					    const char *description TAKES,
					    s8 bias_factor,
					    bool relative,
					    bool dir_out,
					    u64 timestamp)
{
	const struct node_bias *bias;

	bias = set_node_bias(layer, node, description, bias_factor, relative,
			     dir_out, timestamp);
	save_node_bias(layer, bias);
	return bias;
}

void layer_apply_biases(const struct layer *layer,
			const struct gossmap *gossmap,
			s8 *biases)
{
	struct bias *bias;
	struct bias_hash_iter it;
	struct node_bias *node_bias;
	struct node_bias_hash_iter node_it;

	/* We assume bias from individual channels and their node are additive,
	 * this is completely arbitrary. */
	for (node_bias = node_bias_hash_first(layer->node_biases, &node_it);
	     node_bias;
	     node_bias = node_bias_hash_next(layer->node_biases, &node_it)) {
		struct gossmap_node *n;
		struct gossmap_chan *c;
		int dir;
		u32 idx;

		n = gossmap_find_node(gossmap, &node_bias->node);
		if (!n)
			continue;
		for (size_t i = 0; i < n->num_chans; i++) {
			c = gossmap_nth_chan(gossmap, n, i, &dir);
			idx = (gossmap_chan_idx(gossmap, c) << 1) | dir;

			biases[idx] += node_bias->out_bias;
			biases[idx ^ 1] += node_bias->in_bias;
		}
	}

	for (bias = bias_hash_first(layer->biases, &it);
	     bias;
	     bias = bias_hash_next(layer->biases, &it)) {
		struct gossmap_chan *c;

		c = gossmap_find_chan(gossmap, &bias->scidd.scid);
		if (!c)
			continue;
		biases[(gossmap_chan_idx(gossmap, c) << 1) | bias->scidd.dir]
			+= bias->bias;
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
	const struct constraint *c;

	c = add_constraint(layer, scidd, timestamp, min, max);
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
	struct bias_hash_iter biasit;
	struct bias *bias;
	struct node_bias_hash_iter node_it;
	struct node_bias *node_bias;

	for (con = constraint_hash_first(layer->constraints, &conit);
	     con;
	     con = constraint_hash_next(layer->constraints, &conit)) {
		if (con->timestamp < cutoff) {
			constraint_hash_delval(layer->constraints, &conit);
			tal_free(con);
			num_removed++;
		}
	}

	for (bias = bias_hash_first(layer->biases, &biasit); bias;
	     bias = bias_hash_next(layer->biases, &biasit)) {
		if (bias->timestamp < cutoff) {
			bias_hash_delval(layer->biases, &biasit);
			tal_free(bias);
			num_removed++;
		}
	}

	/* FIXME:
	 * Having both in_bias and out_bias bundled in the same node bias
	 * package help us save space. However we end up having a timestamp that
	 * applies to both biases and we lose precision in that.
	 * A possible pathological case is the following:
	 *      - in a certain moment we highly penalize a node A's outgoing
	 *      channels,
	 *      - then we often add or substract a small amount of bias to the
	 *      same node's incoming channels,
	 * As long as we keep updating the incoming channels biases the data
	 * timestamp will never grow old and we will never decay the outgoing
	 * bias that we set at the begining.
	 **/
	for (node_bias = node_bias_hash_first(layer->node_biases, &node_it);
	     node_bias;
	     node_bias = node_bias_hash_next(layer->node_biases, &node_it)) {
		if (node_bias->timestamp < cutoff) {
			node_bias_hash_delval(layer->node_biases, &node_it);
			tal_free(node_bias);
			num_removed++;
		}
	}

	save_complete_layer(layer);
	return num_removed;
}

void layer_add_disabled_node(struct layer *layer, const struct node_id *node)
{
	add_disabled_node(layer, node);
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
	json_add_u64(js, "timestamp", b->timestamp);
	json_object_end(js);
}

void json_add_node_bias(struct json_stream *js,
                        const char *fieldname,
                        const struct node_bias *b,
                        const struct layer *layer)
{
	json_object_start(js, fieldname);
	if (layer)
		json_add_string(js, "layer", layer->name);
	json_add_node_id(js, "node", &b->node);
	if (b->description)
		json_add_string(js, "description", b->description);
	json_add_s64(js, "in_bias", b->in_bias);
	json_add_s64(js, "out_bias", b->out_bias);
	json_add_u64(js, "timestamp", b->timestamp);
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
	struct node_bias_hash_iter node_it;
	const struct node_bias *node_bias;

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
	json_array_start(js, "node_biases");
	for (node_bias = node_bias_hash_first(layer->node_biases, &node_it);
	     node_bias;
	     node_bias = node_bias_hash_next(layer->node_biases, &node_it)) {
		json_add_node_bias(js, NULL, node_bias, NULL);
	}
	json_array_end(js);
	json_object_end(js);
}

void json_add_layers(struct json_stream *js,
		     const struct askrene *askrene,
		     const char *fieldname,
		     const struct layer *layer)
{
	json_array_start(js, fieldname);
	if (layer) {
		json_add_layer(js, NULL, layer);
	} else {
		struct layer_name_hash_iter it;

		for (struct layer *l = layer_name_hash_first(askrene->layers, &it);
		     l;
		     l = layer_name_hash_next(askrene->layers, &it)) {
			json_add_layer(js, NULL, l);
		}
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
