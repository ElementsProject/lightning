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
	bool connect_disable;
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
		return ci->fail(cmd, "fetchinvoice-noconnect set: not initiating a new connection",
				ci->arg);
	}
	plugin_log(cmd->plugin, LOG_DBG, "connecting directly to %s",
		   fmt_pubkey(tmpctx, &ci->dst));

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

	/* Our local additions are always fine, since we checked features then */
	if (gossmap_chan_is_localmod(map, c))
		return true;

	/* Check features of recipient */
	n = gossmap_nth_node(map, c, !dir);
	return gossmap_node_get_feature(map, n, OPT_ONION_MESSAGES) != -1;
}

/* We add fake channels to gossmap to represent current outgoing connections.
 * This allows dijkstra to find transient connections as well. */
static struct gossmap_localmods *
gossmods_from_listpeers(const tal_t *ctx,
			struct command *cmd,
			const struct node_id *self,
			const char *buf,
			const jsmntok_t *toks)
{
	struct gossmap_localmods *mods = gossmap_localmods_new(ctx);
	const jsmntok_t *peers, *peer;
	size_t i;

	peers = json_get_member(buf, toks, "peers");
	json_for_each_arr(i, peer, peers) {
		bool connected;
		struct node_id peer_id;
		const char *err;
		u8 *features = NULL;
		struct short_channel_id fake_scid;

		err = json_scan(tmpctx, buf, peer,
				"{connected:%,"
				"id:%,"
				"features?:%}",
				JSON_SCAN(json_to_bool, &connected),
				JSON_SCAN(json_to_node_id, &peer_id),
				JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex, &features));
		if (err) {
			plugin_err(cmd->plugin, "Bad listpeers.peers %zu: %s", i, err);
		}

		if (!connected || !feature_offered(features, OPT_ONION_MESSAGES))
			continue;

		/* Add a fake channel */
		fake_scid.u64 = i;

		gossmap_local_addchan(mods, self, &peer_id, fake_scid, NULL);
		gossmap_local_updatechan(mods, fake_scid,
					 AMOUNT_MSAT(0),
					 AMOUNT_MSAT(0),
					 0, 0, 0, true, node_id_idx(self, &peer_id));
	}
	return mods;
}

static const struct pubkey *path_to_node(const tal_t *ctx,
					 struct command *cmd,
					 struct gossmap *gossmap,
					 struct plugin *plugin,
					 const char *buf,
					 const jsmntok_t *listpeers,
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
	mods = gossmods_from_listpeers(tmpctx, cmd, &local_nodeid, buf, listpeers);

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
	plugin_log(plugin, LOG_DBG, "Found path to %s: %s(us)",
		   fmt_node_id(tmpctx, &dst_nodeid),
		   fmt_pubkey(tmpctx, local_id));
	for (size_t i = 0; i < tal_count(r); i++) {
		if (!pubkey_from_node_id(&nodes[i+1], &r[i].node_id)) {
			plugin_err(plugin, "Could not convert nodeid %s",
				   fmt_node_id(tmpctx, &r[i].node_id));
		}
		plugin_log(plugin, LOG_DBG, "-> %s",
			   fmt_node_id(tmpctx, &r[i].node_id));
	}

	gossmap_remove_localmods(gossmap, mods);
	return nodes;

fail:
	gossmap_remove_localmods(gossmap, mods);
	return NULL;
}

static struct command_result *listpeers_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct connect_info *ci)
{
	const struct pubkey *path;

	path = path_to_node(tmpctx, cmd,
			    ci->gossmap, cmd->plugin, buf, result,
			    &ci->local_id, &ci->dst);
	if (!path)
		return connect_direct(cmd, ci);

	return ci->cb(cmd, path, ci->arg);
}

struct command_result *establish_onion_path_(struct command *cmd,
					     struct gossmap *gossmap,
					     const struct pubkey *local_id,
					     const struct pubkey *dst,
					     bool connect_disable,
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

	/* We use listpeers here: we don't actually care about channels, just connections! */
	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeers",
				    listpeers_done,
				    command_failed,
				    ci);
	return send_outreq(cmd->plugin, req);
}
