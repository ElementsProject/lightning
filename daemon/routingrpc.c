#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "routing.h"

static void json_add_route(struct command *cmd,
			   const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *srctok, *dsttok, *basetok, *vartok, *delaytok, *minblockstok;
	struct pubkey src, dst;
	u32 base, var, delay, minblocks;

	if (!json_get_params(buffer, params,
			    "src", &srctok,
			    "dst", &dsttok,
			    "base", &basetok,
			    "var", &vartok,
			    "delay", &delaytok,
			    "minblocks", &minblockstok,
			    NULL)) {
		command_fail(cmd, "Need src, dst, base, var, delay & minblocks");
		return;
	}

	if (!pubkey_from_hexstr(buffer + srctok->start,
				srctok->end - srctok->start, &src)) {
		command_fail(cmd, "src %.*s not valid",
			     srctok->end - srctok->start,
			     buffer + srctok->start);
		return;
	}

	if (!pubkey_from_hexstr(buffer + dsttok->start,
				dsttok->end - dsttok->start, &dst)) {
		command_fail(cmd, "dst %.*s not valid",
			     dsttok->end - dsttok->start,
			     buffer + dsttok->start);
		return;
	}

	if (!json_tok_number(buffer, basetok, &base)
	    || !json_tok_number(buffer, vartok, &var)
	    || !json_tok_number(buffer, delaytok, &delay)
	    || !json_tok_number(buffer, minblockstok, &minblocks)) {
		command_fail(cmd,
			     "base, var, delay and minblocks must be numbers");
		return;
	}

	add_connection(cmd->dstate->rstate, &src, &dst, base, var, delay, minblocks);
	command_success(cmd, null_response(cmd));
}

static const struct json_command dev_add_route_command = {
	"dev-add-route",
	json_add_route,
	"Add route from {src} to {dst}, {base} rate in msatoshi, {var} rate in msatoshi, {delay} blocks delay and {minblocks} minimum timeout",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_add_route_command);

static void json_getchannels(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct node_map_iter it;
	struct node *n;
	struct node_map *nodes = cmd->dstate->rstate->nodes;
	struct node_connection *c;
	int num_conn, i;

	json_object_start(response, NULL);
	json_array_start(response, "channels");
	for (n = node_map_first(nodes, &it); n; n = node_map_next(nodes, &it)) {
	        num_conn = tal_count(n->out);
		for (i = 0; i < num_conn; i++){
			c = n->out[i];
			json_object_start(response, NULL);
			json_add_pubkey(response, "from", &n->id);
			json_add_pubkey(response, "to", &c->dst->id);
			json_add_num(response, "base_fee", c->base_fee);
			json_add_num(response, "proportional_fee", c->proportional_fee);
			json_add_num(response, "expiry", c->delay);
			json_add_bool(response, "active", c->active);
			json_object_end(response);
		}
	}
		json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command getchannels_command = {
	"getchannels",
	json_getchannels,
	"List all known channels.",
	"Returns a 'channels' array with all known channels including their fees."
};
AUTODATA(json_command, &getchannels_command);

static void json_routefail(struct command *cmd,
			   const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *enabletok;
	bool enable;

	if (!json_get_params(buffer, params,
			     "enable", &enabletok,
			     NULL)) {
		command_fail(cmd, "Need enable");
		return;
	}

	if (!json_tok_bool(buffer, enabletok, &enable)) {
		command_fail(cmd, "enable must be true or false");
		return;
	}

	log_debug(cmd->dstate->base_log, "dev-routefail: routefail %s",
		  enable ? "enabled" : "disabled");
	cmd->dstate->dev_never_routefail = !enable;

	command_success(cmd, null_response(cmd));
}
static const struct json_command dev_routefail_command = {
	"dev-routefail",
	json_routefail,
	"FAIL htlcs that we can't route if {enable}",
	"Returns an empty result on success"
};
AUTODATA(json_command, &dev_routefail_command);

static void json_getnodes(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct node *n;
	struct node_map_iter i;
	size_t j;

	n = node_map_first(cmd->dstate->rstate->nodes, &i);

	json_object_start(response, NULL);
	json_array_start(response, "nodes");

	while (n != NULL) {
		json_object_start(response, NULL);
		json_add_pubkey(response, "nodeid", &n->id);
		json_array_start(response, "addresses");
		for (j=0; j<tal_count(n->addresses); j++) {
			json_add_address(response, NULL, &n->addresses[j]);
		}
		json_array_end(response);
		json_object_end(response);
		n = node_map_next(cmd->dstate->rstate->nodes, &i);
	}

	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command getnodes_command = {
	"getnodes",
	json_getnodes,
	"List all known nodes in the network.",
	"Returns a 'nodes' array"
};
AUTODATA(json_command, &getnodes_command);
