#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/err/err.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <connectd/connectd_wiregen.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/permissions.h>
#include <lightningd/channel.h>
#include <lightningd/channel_gossip.h>
#include <lightningd/connect_control.h>
#include <lightningd/dual_open_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/notification.h>
#include <lightningd/onion_message.h>
#include <lightningd/opening_common.h>
#include <lightningd/opening_control.h>
#include <lightningd/peer_control.h>
#include <lightningd/plugin_hook.h>

struct connect {
	struct list_node list;
	struct node_id id;
	struct command *cmd;
};

static void destroy_connect(struct connect *c)
{
	list_del(&c->list);
}

static struct connect *new_connect(struct lightningd *ld,
				   const struct node_id *id,
				   struct command *cmd)
{
	struct connect *c = tal(cmd, struct connect);
	c->id = *id;
	c->cmd = cmd;
	list_add_tail(&ld->connects, &c->list);
	tal_add_destructor(c, destroy_connect);
	return c;
}

/* Finds first command which matches. */
static struct connect *find_connect(struct lightningd *ld,
				    const struct node_id *id)
{
	struct connect *i;

	list_for_each(&ld->connects, i, list) {
		if (node_id_eq(&i->id, id))
			return i;
	}
	return NULL;
}

static struct command_result *connect_cmd_succeed(struct command *cmd,
						  const struct peer *peer,
						  bool incoming,
						  const struct wireaddr_internal *addr)
{
	struct json_stream *response = json_stream_success(cmd);
	json_add_node_id(response, "id", &peer->id);
	json_add_hex_talarr(response, "features", peer->their_features);
	json_add_string(response, "direction", incoming ? "in" : "out");
	json_add_address_internal(response, "address", addr);
	return command_success(cmd, response);
}

struct id_and_addr {
	struct node_id id;
	const char *host;
	const u16 *port;
};

static struct command_result *param_id_maybe_addr(struct command *cmd,
						  const char *name,
						  const char *buffer,
						  const jsmntok_t *tok,
						  struct id_and_addr *id_addr)
{
	char *id_str;
	char *atptr;
	char *ataddr = NULL, *host;
	u16 port;
	jsmntok_t idtok = *tok;

	/* Check for id@addrport form */
	id_str = json_strdup(cmd, buffer, &idtok);
	atptr = strchr(id_str, '@');
	if (atptr) {
		int atidx = atptr - id_str;
		ataddr = tal_strdup(cmd, atptr + 1);
		/* Cut id. */
		idtok.end = idtok.start + atidx;
	}

	if (!json_to_node_id(buffer, &idtok, &id_addr->id))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be a node id");

	if (!atptr)
		return NULL;

	/* We could parse port/host in any order, using keyword params. */
	if (id_addr->host) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can't specify host as both xxx@yyy "
				    "and separate argument");
	}

	port = 0;
	if (!separate_address_and_port(cmd, ataddr, &host, &port))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "malformed host @part");

	id_addr->host = host;
	if (port) {
		if (id_addr->port) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Can't specify port as both xxx@yyy:port "
					    "and separate argument");
		}
		id_addr->port = tal_dup(cmd, u16, &port);
	}
	return NULL;
}

static struct command_result *param_id_addr_string(struct command *cmd,
						   const char *name,
						   const char *buffer,
						   const jsmntok_t *tok,
						   const char **addr)
{
	if (*addr) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can't specify host as both xxx@yyy "
				    "and separate argument");
	}
	return param_string(cmd, name, buffer, tok, addr);
}

static struct command_result *param_id_addr_u16(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						const u16 **port)
{
	u16 val;
	if (*port) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can't specify port as both xxx@yyy:port "
				    "and separate argument");
	}
	if (json_to_u16(buffer, tok, &val)) {
		if (val == 0)
			return command_fail_badparam(cmd, name, buffer, tok,
						     "should be non-zero");
		*port = tal_dup(cmd, u16, &val);
		return NULL;
	}

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a 16-bit integer");
}

static struct command_result *json_connect(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct wireaddr_internal *addr;
	const char *err_msg;
	struct id_and_addr id_addr;
	struct peer *peer;

	id_addr.host = NULL;
	id_addr.port = NULL;
	if (!param_check(cmd, buffer, params,
			 p_req("id", param_id_maybe_addr, &id_addr),
			 p_opt("host", param_id_addr_string, &id_addr.host),
			 p_opt("port", param_id_addr_u16, &id_addr.port),
			 NULL))
		return command_param_failed();

	/* If we have a host, convert */
	if (id_addr.host) {
		u16 port = id_addr.port ? *id_addr.port : chainparams_get_ln_port(chainparams);
		addr = tal(cmd, struct wireaddr_internal);
		err_msg = parse_wireaddr_internal(tmpctx, id_addr.host, port,
						  !cmd->ld->always_use_proxy
						  && !cmd->ld->pure_tor_setup, addr);
		if (err_msg) {
			return command_fail(cmd, LIGHTNINGD,
					    "Host %s:%u not valid: %s",
					    id_addr.host, port, err_msg);
		}
		/* Check they didn't specify some weird type! */
		switch (addr->itype) {
		case ADDR_INTERNAL_SOCKNAME:
		case ADDR_INTERNAL_WIREADDR:
		/* Can happen if we're disable DNS */
		case ADDR_INTERNAL_FORPROXY:
			break;
		case ADDR_INTERNAL_ALLPROTO:
		case ADDR_INTERNAL_AUTOTOR:
		case ADDR_INTERNAL_STATICTOR:
			return command_fail(cmd, LIGHTNINGD,
					    "Host %s:%u not a simple type",
					    id_addr.host, port);
		}
	} else {
		addr = NULL;
		/* Port without host name? */
		if (id_addr.port)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Can't specify port without host");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* If we know about peer, see if it's already connected. */
	peer = peer_by_id(cmd->ld, &id_addr.id);
	if (peer && peer->connected == PEER_CONNECTED) {
		log_debug(cmd->ld->log, "Already connected via %s",
			  fmt_wireaddr_internal(tmpctx,
					 &peer->addr));
		return connect_cmd_succeed(cmd, peer,
					   peer->connected_incoming,
					   &peer->addr);
	}

	subd_send_msg(cmd->ld->connectd,
		      take(towire_connectd_connect_to_peer(NULL, &id_addr.id, addr, true, true)));

	/* Leave this here for peer_connected, connect_failed or peer_disconnect_done. */
	new_connect(cmd->ld, &id_addr.id, cmd);
	return command_still_pending(cmd);
}

static const struct json_command connect_command = {
	"connect",
	json_connect,
};
AUTODATA(json_command, &connect_command);

/* We were trying to connect, but they disconnected. */
static void connect_failed(struct lightningd *ld,
			   const struct node_id *id,
			   const struct wireaddr_internal *addrhint,
			   enum jsonrpc_errcode errcode,
			   const char *errmsg)
{
	struct connect *c;

	/* We can have multiple connect commands: fail them all */
	while ((c = find_connect(ld, id)) != NULL) {
		/* They delete themselves from list */
		was_pending(command_fail(c->cmd, errcode, "%s", errmsg));
	}
}

void connect_failed_disconnect(struct lightningd *ld,
			       const struct node_id *id,
			       const struct wireaddr_internal *addrhint)
{
	connect_failed(ld, id, addrhint, CONNECT_DISCONNECTED_DURING,
		       "disconnected during connection");
}

static void handle_connect_failed(struct lightningd *ld, const u8 *msg)
{
	struct node_id id;
	enum jsonrpc_errcode errcode;
	char *errmsg;

	if (!fromwire_connectd_connect_failed(tmpctx, msg, &id, &errcode, &errmsg))
		fatal("Connect gave bad CONNECTD_CONNECT_FAILED message %s",
		      tal_hex(msg, msg));

	connect_failed(ld, &id, NULL, errcode, errmsg);
}

const char *connect_any_cmd_id(const tal_t *ctx,
			       struct lightningd *ld, const struct peer *peer)
{
	struct connect *c = find_connect(ld, &peer->id);
	if (c)
		return tal_strdup(ctx, c->cmd->id);
	return NULL;
}

void connect_succeeded(struct lightningd *ld, const struct peer *peer,
		       bool incoming,
		       const struct wireaddr_internal *addr)
{
	struct connect *c;

	/* We can have multiple connect commands: fail them all */
	while ((c = find_connect(ld, &peer->id)) != NULL) {
		/* They delete themselves from list */
		connect_cmd_succeed(c->cmd, peer, incoming, addr);
	}
}

struct custommsg_payload {
	struct node_id peer_id;
	u8 *msg;
};

static bool custommsg_cb(struct custommsg_payload *payload,
			 const char *buffer, const jsmntok_t *toks)
{
	const jsmntok_t *t_res;

	if (!toks || !buffer)
		return true;

	t_res = json_get_member(buffer, toks, "result");

	/* fail */
	if (!t_res || !json_tok_streq(buffer, t_res, "continue"))
		fatal("Plugin returned an invalid response to the "
		      "custommsg hook: %s", buffer);

	/* call next hook */
	return true;
}

static void custommsg_final(struct custommsg_payload *payload STEALS)
{
	tal_steal(tmpctx, payload);
}

static void custommsg_payload_serialize(struct custommsg_payload *payload,
					struct json_stream *stream,
					struct plugin *plugin)
{
	json_add_hex_talarr(stream, "payload", payload->msg);
	json_add_node_id(stream, "peer_id", &payload->peer_id);
}

REGISTER_PLUGIN_HOOK(custommsg,
		     custommsg_cb,
		     custommsg_final,
		     custommsg_payload_serialize,
		     struct custommsg_payload *);

static void handle_custommsg_in(struct lightningd *ld, const u8 *msg)
{
	struct custommsg_payload *p = tal(NULL, struct custommsg_payload);

	if (!fromwire_connectd_custommsg_in(p, msg, &p->peer_id, &p->msg)) {
		log_broken(ld->log, "Malformed custommsg: %s",
			   tal_hex(tmpctx, msg));
		tal_free(p);
		return;
	}

	notify_custommsg(ld, &p->peer_id, p->msg);
	plugin_hook_call_custommsg(ld, NULL, p);
}

static void connectd_start_shutdown_reply(struct subd *connectd,
					  const u8 *reply,
					  const int *fds UNUSED,
					  void *unused UNUSED)
{
	if (!fromwire_connectd_start_shutdown_reply(reply))
		fatal("Bad connectd_start_shutdown_reply: %s",
		      tal_hex(reply, reply));

	/* Break out of loop now, so we can continue shutdown. */
	log_debug(connectd->ld->log, "io_break: %s", __func__);
	io_break(connectd);
}

void connectd_start_shutdown(struct subd *connectd)
{
	const u8 *msg = towire_connectd_start_shutdown(NULL);

	subd_req(connectd, connectd, take(msg), -1, 0,
		 connectd_start_shutdown_reply, NULL);

	/* Wait for shutdown_reply.  Note that since we're shutting down,
	 * start_json_stream can io_break too! */
	while (io_loop(NULL, NULL) != connectd);
}

void connectd_connect_to_peer(struct lightningd *ld,
			      const struct peer *peer,
			      bool is_important)
{
	/* Give connectd an address if we know it. */
	struct wireaddr_internal *waddr;
	if (peer->last_known_addr) {
		waddr = tal(tmpctx, struct wireaddr_internal);
		wireaddr_internal_from_wireaddr(waddr, peer->last_known_addr);
	} else {
		waddr = NULL;
	}
	subd_send_msg(peer->ld->connectd,
		      take(towire_connectd_connect_to_peer(NULL, &peer->id,
							   waddr, true,
							   !is_important)));
}

void tell_connectd_peer_importance(struct peer *peer,
				   bool was_important)
{
	bool is_important;

	is_important = peer_any_channel(peer,
					channel_important_filter, NULL, NULL);

	/* If this changes the *peer* to important/unimportant, tell connectd */
	if (was_important && !is_important) {
		subd_send_msg(peer->ld->connectd,
			      take(towire_connectd_downgrade_peer(NULL, &peer->id)));
	} else if (!was_important && is_important) {
		/* Tell connectd it's now important (unless we're told not to reconnect) */
		if (peer->ld->reconnect)
			connectd_connect_to_peer(peer->ld, peer, true);
	}
}

static unsigned connectd_msg(struct subd *connectd, const u8 *msg, const int *fds)
{
	enum connectd_wire t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_CONNECTD_INIT:
	case WIRE_CONNECTD_ACTIVATE:
	case WIRE_CONNECTD_CONNECT_TO_PEER:
	case WIRE_CONNECTD_DOWNGRADE_PEER:
	case WIRE_CONNECTD_DISCONNECT_PEER:
	case WIRE_CONNECTD_DEV_MEMLEAK:
	case WIRE_CONNECTD_DEV_SUPPRESS_GOSSIP:
	case WIRE_CONNECTD_DEV_REPORT_FDS:
	case WIRE_CONNECTD_PEER_SEND_MSG:
	case WIRE_CONNECTD_PEER_CONNECT_SUBD:
	case WIRE_CONNECTD_PING:
	case WIRE_CONNECTD_SEND_ONIONMSG:
	case WIRE_CONNECTD_INJECT_ONIONMSG:
	case WIRE_CONNECTD_CUSTOMMSG_OUT:
	case WIRE_CONNECTD_START_SHUTDOWN:
	case WIRE_CONNECTD_SET_CUSTOMMSGS:
	case WIRE_CONNECTD_DEV_EXHAUST_FDS:
	case WIRE_CONNECTD_DEV_SET_MAX_SCIDS_ENCODE_SIZE:
	case WIRE_CONNECTD_SCID_MAP:
	/* This is a reply, so never gets through to here. */
	case WIRE_CONNECTD_INIT_REPLY:
	case WIRE_CONNECTD_ACTIVATE_REPLY:
	case WIRE_CONNECTD_DEV_MEMLEAK_REPLY:
	case WIRE_CONNECTD_PING_REPLY:
	case WIRE_CONNECTD_START_SHUTDOWN_REPLY:
	case WIRE_CONNECTD_INJECT_ONIONMSG_REPLY:
		break;

	case WIRE_CONNECTD_PEER_CONNECTED:
		peer_connected(connectd->ld, msg);
		break;

	case WIRE_CONNECTD_PEER_SPOKE:
		peer_spoke(connectd->ld, msg);
		break;

	case WIRE_CONNECTD_PEER_DISCONNECT_DONE:
		peer_disconnect_done(connectd->ld, msg);
		break;

	case WIRE_CONNECTD_CONNECT_FAILED:
		handle_connect_failed(connectd->ld, msg);
		break;

	case WIRE_CONNECTD_GOT_ONIONMSG_TO_US:
		handle_onionmsg_to_us(connectd->ld, msg);
		break;

	case WIRE_CONNECTD_CUSTOMMSG_IN:
		handle_custommsg_in(connectd->ld, msg);
		break;
	}
	return 0;
}

void force_peer_disconnect(struct lightningd *ld,
			   const struct peer *peer,
			   const char *why)
{
	struct channel *c, *next;

	/* Don't bother on shutting down */
	if (!ld->connectd)
		return;

	/* Disconnect subds */
	if (peer->uncommitted_channel)
		kill_uncommitted_channel(peer->uncommitted_channel, why);

	list_for_each_safe(&peer->channels, c, next, list) {
		if (!c->owner)
			continue;

		log_debug(c->log, "Forcing disconnect due to %s", why);
		/* This frees c! */
		if (channel_state_uncommitted(c->state))
			channel_unsaved_close_conn(c, why);
		else
			channel_set_owner(c, NULL);
	}

	subd_send_msg(peer->ld->connectd,
		      take(towire_connectd_disconnect_peer(NULL, &peer->id,
							peer->connectd_counter)));
}

static void connect_init_done(struct subd *connectd,
			      const u8 *reply,
			      const int *fds UNUSED,
			      void *unused UNUSED)
{
	struct lightningd *ld = connectd->ld;
	char *errmsg;

	if (!fromwire_connectd_init_reply(ld, reply,
					  &ld->binding,
					  &ld->announceable,
					  &errmsg))
		fatal("Bad connectd_init_reply: %s",
		      tal_hex(reply, reply));

	/* connectd can fail in *informative* ways: don't use fatal() here and
	 * confuse things with a backtrace! */
	if (errmsg) {
		log_broken(connectd->log, "%s", errmsg);
		exit(1);
	}

	/* Break out of loop, so we can begin */
	log_debug(connectd->ld->log, "io_break: %s", __func__);
	io_break(connectd);
}

int connectd_init(struct lightningd *ld)
{
	int fds[2];
	u8 *msg;
	int hsmfd;
	struct wireaddr_internal *wireaddrs = ld->proposed_wireaddr;
	enum addr_listen_announce *listen_announce = ld->proposed_listen_announce;
	const char *websocket_helper_path;
	void *ret;

	websocket_helper_path = subdaemon_path(tmpctx, ld,
					       "lightning_websocketd");

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0)
		fatal("Could not socketpair for connectd<->gossipd");

	hsmfd = hsm_get_global_fd(ld, HSM_PERM_ECDH);

	ld->connectd = new_global_subd(ld, "lightning_connectd",
				       connectd_wire_name, connectd_msg,
				       take(&hsmfd), take(&fds[1]),
				       /* Not take(): we share it */
				       ld->dev_disconnect_fd >= 0 ?
				       &ld->dev_disconnect_fd : NULL,
				       NULL);
	if (!ld->connectd)
		err(1, "Could not subdaemon connectd");

	/* If no addr specified, hand wildcard to connectd */
	if (tal_count(wireaddrs) == 0 && ld->autolisten) {
		wireaddrs = tal_arrz(tmpctx, struct wireaddr_internal, 1);
		listen_announce = tal_arr(tmpctx, enum addr_listen_announce, 1);
		wireaddrs->itype = ADDR_INTERNAL_ALLPROTO;
		wireaddrs->u.allproto.is_websocket = false;
		wireaddrs->u.allproto.port = ld->portnum;
		*listen_announce = ADDR_LISTEN_AND_ANNOUNCE;
	} else
		/* Make it clear that autolisten is not active! */
		ld->autolisten = false;

	msg = towire_connectd_init(tmpctx, chainparams,
				   ld->our_features,
				   &ld->our_nodeid,
				   wireaddrs,
				   listen_announce,
				   ld->proxyaddr,
				   ld->always_use_proxy || ld->pure_tor_setup,
				   ld->dev_allow_localhost,
				   ld->config.use_dns,
				   ld->tor_service_password ? ld->tor_service_password : "",
				   ld->config.connection_timeout_secs,
				   websocket_helper_path,
				   !ld->deprecated_ok,
				   ld->dev_fast_gossip,
				   ld->dev_disconnect_fd >= 0,
				   ld->dev_no_ping_timer,
				   ld->dev_handshake_no_reply,
				   ld->dev_throttle_gossip,
				   !ld->reconnect,
				   ld->dev_fast_reconnect,
				   ld->dev_limit_connections_inflight);

	subd_req(ld->connectd, ld->connectd, take(msg), -1, 0,
		 connect_init_done, NULL);

	/* Wait for init_reply */
	ret = io_loop(NULL, NULL);
	log_debug(ld->log, "io_loop: %s", __func__);
	assert(ret == ld->connectd);

	return fds[0];
}

static void connect_activate_done(struct subd *connectd,
				  const u8 *reply,
				  const int *fds UNUSED,
				  void *unused UNUSED)
{
	char *errmsg;
	if (!fromwire_connectd_activate_reply(reply, reply, &errmsg))
		fatal("Bad connectd_activate_reply: %s",
		      tal_hex(reply, reply));

	/* connectd can fail in *informative* ways: don't use fatal() here and
	 * confuse things with a backtrace! */
	if (errmsg) {
		log_broken(connectd->log, "%s", errmsg);
		exit(1);
	}

	/* Break out of loop, so we can begin */
	log_debug(connectd->ld->log, "io_break: %s", __func__);
	io_break(connectd);
}

void tell_connectd_scid(struct lightningd *ld,
			struct short_channel_id scid,
			const struct node_id *peer_id)
{
	subd_send_msg(ld->connectd,
		      take(towire_connectd_scid_map(NULL,
						    scid,
						    peer_id)));
}

void connectd_activate(struct lightningd *ld)
{
	void *ret;
	const u8 *msg;
	struct peer *peer;
	struct channel *channel;
	struct peer_node_id_map_iter it;

	/* Tell connectd about all aliases/scids for known peers */
	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		list_for_each(&peer->channels, channel, list) {
			if (channel->alias[LOCAL])
				tell_connectd_scid(ld, *channel->alias[LOCAL], &peer->id);
			if (channel->scid &&
			    (channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL)) {
				tell_connectd_scid(ld, *channel->scid, &peer->id);
			}
		}
	}

	msg = towire_connectd_activate(NULL, ld->listen);
	subd_req(ld->connectd, ld->connectd, take(msg), -1, 0,
		 connect_activate_done, NULL);

	/* Wait for activate_reply */
	ret = io_loop(NULL, NULL);
	log_debug(ld->log, "io_loop: %s", __func__);
	assert(ret == ld->connectd);
}

static struct command_result *json_sendcustommsg(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	struct node_id *dest;
	struct peer *peer;
	u8 *msg;
	int type;

	if (!param_check(cmd, buffer, params,
			 p_req("node_id", param_node_id, &dest),
			 p_req("msg", param_bin_from_hex, &msg),
			 NULL))
		return command_param_failed();

	type = fromwire_peektype(msg);

	/* Allow peer_storage and your_peer_storage msgtypes */
	if (peer_wire_is_internal(type)) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_REQUEST,
		    "Cannot send messages of type %d (%s). It is not possible "
		    "to send messages that have a type managed internally "
		    "since that might cause issues with the internal state "
		    "tracking.",
		    type, peer_wire_name(type));
	}

	if (type % 2 == 0) {
		/* INFO the first time, then DEBUG */
		static enum log_level level = LOG_INFORM;
		log_(cmd->ld->log, level, dest, false,
		     "sendcustommsg id=%s sending a custom even message (%u)",
		     cmd->id, type);
		level = LOG_DBG;
	}

	peer = peer_by_id(cmd->ld, dest);
	if (!peer) {
		return command_fail(cmd, JSONRPC2_INVALID_REQUEST,
				    "No such peer: %s",
				    fmt_node_id(cmd, dest));
	}

	/* We allow messages from plugins responding to peer_connected hook,
	 * so can be PEER_CONNECTING. */
	if (peer->connected == PEER_DISCONNECTED)
		return command_fail(cmd, JSONRPC2_INVALID_REQUEST,
				    "Peer is not connected");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	subd_send_msg(cmd->ld->connectd,
		      take(towire_connectd_custommsg_out(cmd, dest, msg)));

	response = json_stream_success(cmd);
	json_add_string(response, "status",
			"Message sent to connectd for delivery");

	return command_success(cmd, response);
}

static const struct json_command sendcustommsg_command = {
    "sendcustommsg",
    json_sendcustommsg,
};

AUTODATA(json_command, &sendcustommsg_command);

static struct command_result *json_dev_suppress_gossip(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	subd_send_msg(cmd->ld->connectd,
		      take(towire_connectd_dev_suppress_gossip(NULL)));
	cmd->ld->dev_suppress_gossip = true;

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_suppress_gossip = {
	"dev-suppress-gossip",
	json_dev_suppress_gossip,
	.dev_only = true,
};
AUTODATA(json_command, &dev_suppress_gossip);

static struct command_result *json_dev_report_fds(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *obj UNNEEDED,
						  const jsmntok_t *params)
{
	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	subd_send_msg(cmd->ld->connectd,
		      take(towire_connectd_dev_report_fds(NULL)));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_report_fds = {
	"dev-report-fds",
	json_dev_report_fds,
	.dev_only = true,
};
AUTODATA(json_command, &dev_report_fds);

static struct command_result *json_dev_connectd_exhaust_fds(struct command *cmd,
							    const char *buffer,
							    const jsmntok_t *obj UNNEEDED,
							    const jsmntok_t *params)
{
	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	subd_send_msg(cmd->ld->connectd,
		      take(towire_connectd_dev_exhaust_fds(NULL)));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_connectd_exhaust_fds = {
	"dev-connectd-exhaust-fds",
	json_dev_connectd_exhaust_fds,
	.dev_only = true,
};
AUTODATA(json_command, &dev_connectd_exhaust_fds);
