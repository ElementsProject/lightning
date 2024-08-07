/* All your payment questions answered!
 *
 * This powerful oracle combines data from the network, and then
 * determines optimal routes.
 *
 * When you feed it information, these are remembered as "layers", so you
 * can ask questions with (or without) certain layers.
 */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/route.h>
#include <errno.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/reserve.h>
#include <plugins/libplugin.h>

static struct askrene *get_askrene(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct askrene);
}

/* JSON helpers */
static struct command_result *param_string_array(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 const char ***arr)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok, "should be an array");

	*arr = tal_arr(cmd, const char *, tok->size);
	json_for_each_arr(i, t, tok) {
		if (t->type != JSMN_STRING)
			return command_fail_badparam(cmd, name, buffer, t, "should be a string");
		(*arr)[i] = json_strdup(*arr, buffer, t);
	}
	return NULL;
}

static struct command_result *param_known_layer(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						struct layer **layer)
{
	const char *layername;
	struct command_result *ret = param_string(cmd, name, buffer, tok, &layername);
	if (ret)
		return ret;

	*layer = find_layer(get_askrene(cmd->plugin), layername);
	tal_free(layername);
	if (!*layer)
		return command_fail_badparam(cmd, name, buffer, tok, "Unknown layer");
	return NULL;
}

static bool json_to_zero_or_one(const char *buffer, const jsmntok_t *tok, int *num)
{
	u32 v32;
	if (!json_to_u32(buffer, tok, &v32))
		return false;
	if (v32 != 0 && v32 != 1)
		return false;
	*num = v32;
	return true;
}

static struct command_result *param_zero_or_one(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						int **num)
{
	*num = tal(cmd, int);
	if (json_to_zero_or_one(buffer, tok, *num))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be 0 or 1");
}

struct reserve_path {
	struct short_channel_id_dir *scidds;
	struct amount_msat *amounts;
};

static struct command_result *parse_reserve_path(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct short_channel_id_dir *scidd,
						 struct amount_msat *amount)
{
	const char *err;

	err = json_scan(tmpctx, buffer, tok, "{short_channel_id:%,direction:%,amount_msat:%s}",
			JSON_SCAN(json_to_short_channel_id, &scidd->scid),
			JSON_SCAN(json_to_zero_or_one, &scidd->dir),
			JSON_SCAN(json_to_msat, amount));
	if (err)
		return command_fail_badparam(cmd, name, buffer, tok, err);
	return NULL;
}

static struct command_result *param_reserve_path(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct reserve_path **path)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok, "should be an array");

	*path = tal(cmd, struct reserve_path);
	(*path)->scidds = tal_arr(cmd, struct short_channel_id_dir, tok->size);
	(*path)->amounts = tal_arr(cmd, struct amount_msat, tok->size);
	json_for_each_arr(i, t, tok) {
		struct command_result *ret;

		ret = parse_reserve_path(cmd, name, buffer, t,
					 &(*path)->scidds[i],
					 &(*path)->amounts[i]);
		if (ret)
			return ret;
	}
	return NULL;
}

/* Returns an error message, or sets *routes */
static const char *get_routes(struct command *cmd,
			      const struct node_id *source,
			      const struct node_id *dest,
			      struct amount_msat amount,
			      const char **layers,
			      struct route ***routes)
{
	/* FIXME: Do route here!  This is a dummy, single "direct" route. */
	*routes = tal_arr(cmd, struct route *, 1);
	(*routes)[0]->success_prob = 1;
	(*routes)[0]->hops = tal_arr((*routes)[0], struct route_hop, 1);
	(*routes)[0]->hops[0].scid.u64 = 0x0000010000020003ULL;
	(*routes)[0]->hops[0].direction = 0;
	(*routes)[0]->hops[0].node_id = *dest;
	(*routes)[0]->hops[0].amount = amount;
	(*routes)[0]->hops[0].delay = 6;

	return NULL;
}

static struct command_result *json_getroutes(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *params)
{
	struct node_id *dest, *source;
	const char **layers;
	struct amount_msat *amount;
	struct route **routes;
	struct json_stream *response;
	const char *err;

	if (!param(cmd, buffer, params,
		   p_req("source", param_node_id, &source),
		   p_req("destination", param_node_id, &dest),
		   p_req("amount_msat", param_msat, &amount),
		   p_req("layers", param_string_array, &layers),
		   NULL))
		return command_param_failed();

	err = get_routes(cmd, source, dest, *amount, layers, &routes);
	if (err)
		return command_fail(cmd, PAY_ROUTE_NOT_FOUND, "%s", err);

	response = jsonrpc_stream_success(cmd);
	json_object_start(response, "routes");
	json_array_start(response, "routes");
	for (size_t i = 0; i < tal_count(routes); i++) {
		json_add_u64(response, "probability_ppm", (u64)(routes[i]->success_prob * 1000000));
		json_array_start(response, "path");
		for (size_t j = 0; j < tal_count(routes[i]->hops); j++) {
			const struct route_hop *r = &routes[i]->hops[j];
			json_add_short_channel_id(response, "short_channel_id", r->scid);
			json_add_u32(response, "direction", r->direction);
			json_add_node_id(response, "node_id", &r->node_id);
			json_add_amount_msat(response, "amount", r->amount);
			json_add_u32(response, "delay", r->delay);
		}
		json_array_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_reserve(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *params)
{
	struct reserve_path *path;
	struct json_stream *response;
	size_t num;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("path", param_reserve_path, &path),
		   NULL))
		return command_param_failed();

	num = reserves_add(askrene->reserved, path->scidds, path->amounts,
			   tal_count(path->scidds));
	if (num != tal_count(path->scidds)) {
		const struct reserve *r = find_reserve(askrene->reserved, &path->scidds[num]);
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Overflow reserving %zu: %s amount %s (%s reserved already)",
				    num,
				    fmt_short_channel_id_dir(tmpctx, &path->scidds[num]),
				    fmt_amount_msat(tmpctx, path->amounts[num]),
				    r ? fmt_amount_msat(tmpctx, r->amount) : "none");
	}

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_unreserve(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *params)
{
	struct reserve_path *path;
	struct json_stream *response;
	size_t num;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("path", param_reserve_path, &path),
		   NULL))
		return command_param_failed();

	num = reserves_remove(askrene->reserved, path->scidds, path->amounts,
			      tal_count(path->scidds));
	if (num != tal_count(path->scidds)) {
		const struct reserve *r = find_reserve(askrene->reserved, &path->scidds[num]);
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Underflow unreserving %zu: %s amount %s (%zu reserved, amount %s)",
				    num,
				    fmt_short_channel_id_dir(tmpctx, &path->scidds[num]),
				    fmt_amount_msat(tmpctx, path->amounts[num]),
				    r ? r->num_htlcs : 0,
				    r ? fmt_amount_msat(tmpctx, r->amount) : "none");
	}

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_create_channel(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *params)
{
	const char *layername;
	struct layer *layer;
	const struct local_channel *lc;
	struct node_id *src, *dst;
	struct short_channel_id *scid;
	struct amount_msat *capacity;
	struct json_stream *response;
	struct amount_msat *htlc_min, *htlc_max, *base_fee;
	u32 *proportional_fee;
	u16 *delay;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_string, &layername),
			 p_req("source", param_node_id, &src),
			 p_req("destination", param_node_id, &dst),
			 p_req("short_channel_id", param_short_channel_id, &scid),
			 p_req("capacity_msat", param_msat, &capacity),
			 p_req("htlc_minimum_msat", param_msat, &htlc_min),
			 p_req("htlc_maximum_msat", param_msat, &htlc_max),
			 p_req("fee_base_msat", param_msat, &base_fee),
			 p_req("fee_proportional_millionths", param_u32, &proportional_fee),
			 p_req("delay", param_u16, &delay),
			 NULL))
		return command_param_failed();

	/* If it exists, it must match */
	layer = find_layer(askrene, layername);
	if (layer) {
		lc = layer_find_local_channel(layer, *scid);
		if (lc && !layer_check_local_channel(lc, src, dst, *capacity)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "channel already exists with different values!");
		}
	} else
		lc = NULL;

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!layer)
		layer = new_layer(askrene, layername);

	layer_update_local_channel(layer, src, dst, *scid, *capacity,
				   *base_fee, *proportional_fee, *delay,
				   *htlc_min, *htlc_max);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_inform_channel(struct command *cmd,
							    const char *buffer,
							    const jsmntok_t *params)
{
	struct layer *layer;
	const char *layername;
	struct short_channel_id *scid;
	int *direction;
	struct json_stream *response;
	struct amount_msat *max, *min;
	const struct constraint *c;
	struct short_channel_id_dir scidd;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_string, &layername),
			 p_req("short_channel_id", param_short_channel_id, &scid),
			 p_req("direction", param_zero_or_one, &direction),
			 p_opt("minimum_msat", param_msat, &min),
			 p_opt("maximum_msat", param_msat, &max),
			 NULL))
		return command_param_failed();

	if ((!min && !max) || (min && max)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Must specify exactly one of maximum_msat/minimum_msat");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	layer = find_layer(askrene, layername);
	if (!layer)
		layer = new_layer(askrene, layername);

	/* Calls expect a convenient short_channel_id_dir struct */
	scidd.scid = *scid;
	scidd.dir = *direction;

	if (min) {
		c = layer_update_constraint(layer, &scidd, CONSTRAINT_MIN,
					    time_now().ts.tv_sec, *min);
	} else {
		c = layer_update_constraint(layer, &scidd, CONSTRAINT_MAX,
					    time_now().ts.tv_sec, *max);
	}
	response = jsonrpc_stream_success(cmd);
	json_add_constraint(response, "constraint", c, layer);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_disable_node(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct node_id *node;
	const char *layername;
	struct layer *layer;
	struct json_stream *response;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("layer", param_string, &layername),
		   p_req("node", param_node_id, &node),
		   NULL))
		return command_param_failed();

	layer = find_layer(askrene, layername);
	if (!layer)
		layer = new_layer(askrene, layername);

	/* We save this in the layer, because they want us to disable all the channels
	 * to the node at *use* time (a new channel might be gossiped!). */
	layer_add_disabled_node(layer, node);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_listlayers(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	const char *layername;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_opt("layer", param_string, &layername),
		   NULL))
		return command_param_failed();

	response = jsonrpc_stream_success(cmd);
	json_add_layers(response, askrene, "layers", layername);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_age(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	struct layer *layer;
	struct json_stream *response;
	u64 *cutoff;
	size_t num_removed;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("cutoff", param_u64, &cutoff),
		   NULL))
		return command_param_failed();

	num_removed = layer_trim_constraints(layer, *cutoff);

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "layer", layer_name(layer));
	json_add_u64(response, "num_removed", num_removed);
	return command_finished(cmd, response);
}

static const struct plugin_command commands[] = {
	{
		"getroutes",
		json_getroutes,
	},
	{
		"askrene-reserve",
		json_askrene_reserve,
	},
	{
		"askrene-unreserve",
		json_askrene_unreserve,
	},
	{
		"askrene-disable-node",
		json_askrene_disable_node,
	},
	{
		"askrene-create-channel",
		json_askrene_create_channel,
	},
	{
		"askrene-inform-channel",
		json_askrene_inform_channel,
	},
	{
		"askrene-listlayers",
		json_askrene_listlayers,
	},
	{
		"askrene-age",
		json_askrene_age,
	},
};

static void askrene_markmem(struct plugin *plugin, struct htable *memtable)
{
	layer_memleak_mark(get_askrene(plugin), memtable);
}

static const char *init(struct plugin *plugin,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct askrene *askrene = tal(plugin, struct askrene);
	askrene->plugin = plugin;
	list_head_init(&askrene->layers);
	askrene->reserved = new_reserve_hash(askrene);
	askrene->gossmap = gossmap_load(askrene, GOSSIP_STORE_FILENAME, NULL);

	if (!askrene->gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));

	plugin_set_data(plugin, askrene);
	plugin_set_memleak_handler(plugin, askrene_markmem);
	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, NULL, PLUGIN_RESTARTABLE, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0, NULL);
}
