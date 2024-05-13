#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_stream.h>
#include <common/route.h>
#include <plugins/establish_onion_path.h>

struct connect_info {
	struct pubkey local_id, dst;
	const char *connect_disable;
	struct gossmap *gossmap;
	struct command_result *(*cb)(struct command *,
				     const struct pubkey *,
				     void *arg);
	struct command_result *(*fail)(struct command *, const char *,
				       void *arg);
	void *arg;
};

static struct command_result *connect_ok(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *result,
					 struct connect_info *ci)
{
	struct pubkey *path = tal_arr(tmpctx, struct pubkey, 2);

	/* Create direct mini-path */
	path[0] = ci->local_id;
	path[1] = ci->dst;

	return ci->cb(cmd, path, ci->arg);
}

static struct command_result *command_failed(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct connect_info *ci)
{
	return ci->fail(cmd, json_strdup(tmpctx, buf, result), ci->arg);
}

static struct command_result *connect_direct(struct command *cmd,
					     struct connect_info *ci)
{
	struct out_req *req;

	if (ci->connect_disable) {
		return ci->fail(cmd,
				tal_fmt(tmpctx, "%s set: not initiating a new connection",
					ci->connect_disable),
				ci->arg);
	}

	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "connect", connect_ok, command_failed, ci);
	json_add_pubkey(req->js, "id", &ci->dst);
	return send_outreq(cmd->plugin, req);
}

static bool can_carry_onionmsg(const struct gossmap *map,
			       const struct gossmap_chan *c,
			       int dir,
			       struct amount_msat amount UNUSED,
			       void *arg UNUSED)
{
	const struct gossmap_node *n;
	/* Don't use it if either side says it's disabled */
	if (!c->half[dir].enabled || !c->half[!dir].enabled)
		return false;

	/* Check features of recipient */
	n = gossmap_nth_node(map, c, !dir);
	return gossmap_node_get_feature(map, n, OPT_ONION_MESSAGES) != -1;
}

static const struct pubkey *path_to_node(const tal_t *ctx,
					 struct gossmap *gossmap,
					 struct plugin *plugin,
					 const char *buf,
					 const jsmntok_t *listpeerchannels,
					 const struct pubkey *local_id,
					 const struct pubkey *dst_key)
{
	struct route_hop *r;
	const struct dijkstra *dij;
	const struct gossmap_node *src;
	const struct gossmap_node *dst;
	struct pubkey *nodes;
	struct gossmap_localmods *mods;
	struct node_id local_nodeid, dst_nodeid;

	node_id_from_pubkey(&local_nodeid, local_id);
	node_id_from_pubkey(&dst_nodeid, dst_key);
	mods = gossmods_from_listpeerchannels(tmpctx, &local_nodeid, buf, listpeerchannels,
					      false, gossmod_add_localchan, NULL);

	gossmap_apply_localmods(gossmap, mods);
	dst = gossmap_find_node(gossmap, &dst_nodeid);
	if (!dst)
		goto fail;

	/* If we don't exist in gossip, routing can't happen. */
	src = gossmap_find_node(gossmap, &local_nodeid);
	if (!src)
		goto fail;

	dij = dijkstra(tmpctx, gossmap, dst, AMOUNT_MSAT(0), 0,
		       can_carry_onionmsg, route_score_shorter, NULL);

	r = route_from_dijkstra(tmpctx, gossmap, dij, src, AMOUNT_MSAT(0), 0);
	if (!r)
		goto fail;

	nodes = tal_arr(ctx, struct pubkey, tal_count(r) + 1);
	nodes[0] = *local_id;
	for (size_t i = 0; i < tal_count(r); i++) {
		if (!pubkey_from_node_id(&nodes[i+1], &r[i].node_id)) {
			plugin_err(plugin, "Could not convert nodeid %s",
				   fmt_node_id(tmpctx, &r[i].node_id));
		}
	}

	gossmap_remove_localmods(gossmap, mods);
	return nodes;

fail:
	gossmap_remove_localmods(gossmap, mods);
	return NULL;
}

static struct command_result *listpeerchannels_done(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *result,
						    struct connect_info *ci)
{
	const struct pubkey *path;

	path = path_to_node(tmpctx, ci->gossmap, cmd->plugin, buf, result,
			    &ci->local_id, &ci->dst);
	if (!path)
		return connect_direct(cmd, ci);

	return ci->cb(cmd, path, ci->arg);
}

struct command_result *establish_onion_path_(struct command *cmd,
					     struct gossmap *gossmap,
					     const struct pubkey *local_id,
					     const struct pubkey *dst,
					     const char *connect_disable,
					     struct command_result *(*success)(struct command *,
									       const struct pubkey *,
									       void *arg),
					     struct command_result *(*fail)(struct command *,
									    const char *why,
									    void *arg),
					     void *arg)
{
	struct connect_info *ci = tal(cmd, struct connect_info);
	struct out_req *req;

	ci->local_id = *local_id;
	ci->dst = *dst;
	ci->cb = success;
	ci->fail = fail;
	ci->arg = arg;
	ci->connect_disable = connect_disable;
	ci->gossmap = gossmap;

	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    listpeerchannels_done,
				    command_failed,
				    ci);
	return send_outreq(cmd->plugin, req);
}
