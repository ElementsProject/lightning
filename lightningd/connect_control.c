#include "config.h"
#include <ccan/err/err.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/json_tok.h>
#include <common/memleak.h>
#include <common/param.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <connectd/connectd_wiregen.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/capabilities.h>
#include <lightningd/channel.h>
#include <lightningd/connect_control.h>
#include <lightningd/dual_open_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
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

/* FIXME: Reorder! */
static void try_connect(const tal_t *ctx,
			struct lightningd *ld,
			const struct node_id *id,
			u32 seconds_delay,
			const struct wireaddr_internal *addrhint);

static struct command_result *json_connect(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	u32 *port;
	jsmntok_t *idtok;
	struct node_id id;
	char *id_str;
	char *atptr;
	char *ataddr = NULL;
	const char *name;
	struct wireaddr_internal *addr;
	const char *err_msg;

	if (!param(cmd, buffer, params,
		   p_req("id", param_tok, (const jsmntok_t **) &idtok),
		   p_opt("host", param_string, &name),
		   p_opt("port", param_number, &port),
		   NULL))
		return command_param_failed();

	/* Check for id@addrport form */
	id_str = json_strdup(cmd, buffer, idtok);
	atptr = strchr(id_str, '@');
	if (atptr) {
		int atidx = atptr - id_str;
		ataddr = tal_strdup(cmd, atptr + 1);
		/* Cut id. */
		idtok->end = idtok->start + atidx;
	}

	if (!json_to_node_id(buffer, idtok, &id)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "id %.*s not valid",
				    json_tok_full_len(idtok),
				    json_tok_full(buffer, idtok));
	}

	if (name && ataddr) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can't specify host as both xxx@yyy "
				    "and separate argument");
	}

	/* Get parseable host if provided somehow */
	if (!name && ataddr)
		name = ataddr;

	/* Port without host name? */
	if (port && !name) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can't specify port without host");
	}

	/* Was there parseable host name? */
	if (name) {
		/* Is there a port? */
		if (!port) {
			port = tal(cmd, u32);
			*port = DEFAULT_PORT;
		}
		addr = tal(cmd, struct wireaddr_internal);
		if (!parse_wireaddr_internal(name, addr, *port, false,
					     !cmd->ld->always_use_proxy
					     && !cmd->ld->pure_tor_setup,
					     true, deprecated_apis,
					     &err_msg)) {
			return command_fail(cmd, LIGHTNINGD,
					    "Host %s:%u not valid: %s",
					    name, *port,
					    err_msg ? err_msg : "port is 0");
		}
	} else
		addr = NULL;

	try_connect(cmd, cmd->ld, &id, 0, addr);

	/* Leave this here for peer_connected or connect_failed. */
	new_connect(cmd->ld, &id, cmd);
	return command_still_pending(cmd);
}

static const struct json_command connect_command = {
	"connect",
	"network",
	json_connect,
	"Connect to {id} at {host} (which can end in ':port' if not default). "
	"{id} can also be of the form id@host"
};
AUTODATA(json_command, &connect_command);

/* We actually use this even if we don't need a delay, while we talk to
 * gossipd to get the addresses. */
struct delayed_reconnect {
	struct lightningd *ld;
	struct node_id id;
	u32 seconds_delayed;
	struct wireaddr_internal *addrhint;
};

static void gossipd_got_addrs(struct subd *subd,
			      const u8 *msg,
			      const int *fds,
			      struct delayed_reconnect *d)
{
	struct wireaddr *addrs;
	u8 *connectmsg;

	if (!fromwire_gossipd_get_addrs_reply(tmpctx, msg, &addrs))
		fatal("Gossipd gave bad GOSSIPD_GET_ADDRS_REPLY %s",
		      tal_hex(msg, msg));

	connectmsg = towire_connectd_connect_to_peer(NULL,
						     &d->id,
						     d->seconds_delayed,
						     addrs,
						     d->addrhint);
	subd_send_msg(d->ld->connectd, take(connectmsg));
	tal_free(d);
}

/* We might be off a delay timer.  Now ask gossipd about public addresses. */
static void do_connect(struct delayed_reconnect *d)
{
	u8 *msg = towire_gossipd_get_addrs(NULL, &d->id);

	subd_req(d, d->ld->gossip, take(msg), -1, 0, gossipd_got_addrs, d);
}

/* peer may be NULL here */
static void try_connect(const tal_t *ctx,
			struct lightningd *ld,
			const struct node_id *id,
			u32 seconds_delay,
			const struct wireaddr_internal *addrhint)
{
	struct delayed_reconnect *d;
	struct peer *peer;

	d = tal(ctx, struct delayed_reconnect);
	d->ld = ld;
	d->id = *id;
	d->seconds_delayed = seconds_delay;
	d->addrhint = tal_dup_or_null(d, struct wireaddr_internal, addrhint);

	if (!seconds_delay) {
		do_connect(d);
		return;
	}

	log_peer_debug(ld->log, id, "Will try reconnect in %u seconds",
		       seconds_delay);
	/* Update any channel billboards */
	peer = peer_by_id(ld, id);
	if (peer) {
		struct channel *channel;
		list_for_each(&peer->channels, channel, list) {
			if (!channel_active(channel))
				continue;
			channel_set_billboard(channel, false,
					      tal_fmt(tmpctx,
						      "Will attempt reconnect "
						      "in %u seconds",
						      seconds_delay));
		}
	}

	/* We fuzz the timer by up to 1 second, to avoid getting into
	 * simultanous-reconnect deadlocks with peer. */
	notleak(new_reltimer(ld->timers, d,
			     timerel_add(time_from_sec(seconds_delay),
					 time_from_usec(pseudorand(1000000))),
			     do_connect, d));
}

void try_reconnect(const tal_t *ctx,
		   struct peer *peer,
		   u32 seconds_delay,
		   const struct wireaddr_internal *addrhint)
{
	if (!peer->ld->reconnect)
		return;

	try_connect(ctx,
		    peer->ld,
		    &peer->id,
		    seconds_delay,
		    addrhint);
}

static void connect_failed(struct lightningd *ld, const u8 *msg)
{
	struct node_id id;
	errcode_t errcode;
	char *errmsg;
	struct connect *c;
	u32 seconds_to_delay;
	struct wireaddr_internal *addrhint;
	struct peer *peer;

	if (!fromwire_connectd_connect_failed(tmpctx, msg, &id, &errcode, &errmsg,
						&seconds_to_delay, &addrhint))
		fatal("Connect gave bad CONNECTD_CONNECT_FAILED message %s",
		      tal_hex(msg, msg));

	/* We can have multiple connect commands: fail them all */
	while ((c = find_connect(ld, &id)) != NULL) {
		/* They delete themselves from list */
		was_pending(command_fail(c->cmd, errcode, "%s", errmsg));
	}

	/* If we have an active channel, then reconnect. */
	peer = peer_by_id(ld, &id);
	if (peer) {
		if (peer_any_active_channel(peer, NULL))
			try_reconnect(peer, peer, seconds_to_delay, addrhint);
	}
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

static void peer_already_connected(struct lightningd *ld, const u8 *msg)
{
	struct node_id id;
	struct peer *peer;

	if (!fromwire_connectd_peer_already_connected(msg, &id))
		fatal("Bad msg %s from connectd", tal_hex(tmpctx, msg));

	peer = peer_by_id(ld, &id);
	if (peer)
		connect_succeeded(ld, peer,
				  peer->connected_incoming,
				  &peer->addr);
}

static void peer_please_disconnect(struct lightningd *ld, const u8 *msg)
{
	struct node_id id;
	struct peer *peer;
	struct channel *c, **channels;

	if (!fromwire_connectd_reconnected(msg, &id))
		fatal("Bad msg %s from connectd", tal_hex(tmpctx, msg));

	peer = peer_by_id(ld, &id);
	if (!peer)
		return;

	/* Freeing channels can free peer, so gather first. */
	channels = tal_arr(tmpctx, struct channel *, 0);
	list_for_each(&peer->channels, c, list)
		tal_arr_expand(&channels, c);

	if (peer->uncommitted_channel)
		kill_uncommitted_channel(peer->uncommitted_channel,
					 "Reconnected");

	for (size_t i = 0; i < tal_count(channels); i++) {
		c = channels[i];
		if (channel_active(c)) {
			channel_cleanup_commands(c, "Reconnected");
			channel_fail_reconnect(c, "Reconnected");
		} else if (channel_unsaved(c)) {
			log_info(c->log, "Killing opening daemon: Reconnected");
			channel_unsaved_close_conn(c, "Reconnected");
		}
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

	plugin_hook_call_custommsg(ld, p);
}

static unsigned connectd_msg(struct subd *connectd, const u8 *msg, const int *fds)
{
	enum connectd_wire t = fromwire_peektype(msg);

	switch (t) {
	/* These are messages we send, not them. */
	case WIRE_CONNECTD_INIT:
	case WIRE_CONNECTD_ACTIVATE:
	case WIRE_CONNECTD_CONNECT_TO_PEER:
	case WIRE_CONNECTD_DISCARD_PEER:
	case WIRE_CONNECTD_DEV_MEMLEAK:
	case WIRE_CONNECTD_DEV_SUPPRESS_GOSSIP:
	case WIRE_CONNECTD_PEER_FINAL_MSG:
	case WIRE_CONNECTD_PEER_MAKE_ACTIVE:
	case WIRE_CONNECTD_PING:
	case WIRE_CONNECTD_SEND_ONIONMSG:
	case WIRE_CONNECTD_CUSTOMMSG_OUT:
	/* This is a reply, so never gets through to here. */
	case WIRE_CONNECTD_INIT_REPLY:
	case WIRE_CONNECTD_ACTIVATE_REPLY:
	case WIRE_CONNECTD_DEV_MEMLEAK_REPLY:
	case WIRE_CONNECTD_PING_REPLY:
		break;

	case WIRE_CONNECTD_RECONNECTED:
		peer_please_disconnect(connectd->ld, msg);
		break;

	case WIRE_CONNECTD_PEER_CONNECTED:
		peer_connected(connectd->ld, msg);
		break;

	case WIRE_CONNECTD_PEER_ACTIVE:
		if (tal_count(fds) != 1)
			return 1;
		peer_active(connectd->ld, msg, fds[0]);
		break;

	case WIRE_CONNECTD_PEER_DISCONNECT_DONE:
		peer_disconnect_done(connectd->ld, msg);
		break;

	case WIRE_CONNECTD_PEER_ALREADY_CONNECTED:
		peer_already_connected(connectd->ld, msg);
		break;

	case WIRE_CONNECTD_CONNECT_FAILED:
		connect_failed(connectd->ld, msg);
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

static void connect_init_done(struct subd *connectd,
			      const u8 *reply,
			      const int *fds UNUSED,
			      void *unused UNUSED)
{
	struct lightningd *ld = connectd->ld;
	char *errmsg;

	log_debug(connectd->log, "connectd_init_done");
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

	websocket_helper_path = subdaemon_path(tmpctx, ld,
					       "lightning_websocketd");

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != 0)
		fatal("Could not socketpair for connectd<->gossipd");

	hsmfd = hsm_get_global_fd(ld, HSM_CAP_ECDH);

	ld->connectd = new_global_subd(ld, "lightning_connectd",
				       connectd_wire_name, connectd_msg,
				       take(&hsmfd), take(&fds[1]),
#if DEVELOPER
				       /* Not take(): we share it */
				       ld->dev_disconnect_fd >= 0 ?
				       &ld->dev_disconnect_fd : NULL,
#endif
				       NULL);
	if (!ld->connectd)
		err(1, "Could not subdaemon connectd");

	/* If no addr specified, hand wildcard to connectd */
	if (tal_count(wireaddrs) == 0 && ld->autolisten) {
		wireaddrs = tal_arrz(tmpctx, struct wireaddr_internal, 1);
		listen_announce = tal_arr(tmpctx, enum addr_listen_announce, 1);
		wireaddrs->itype = ADDR_INTERNAL_ALLPROTO;
		wireaddrs->u.port = ld->portnum;
		*listen_announce = ADDR_LISTEN_AND_ANNOUNCE;
	}

	msg = towire_connectd_init(
	    tmpctx, chainparams,
	    ld->our_features,
	    &ld->id,
	    wireaddrs,
	    listen_announce,
	    ld->proxyaddr, ld->always_use_proxy || ld->pure_tor_setup,
	    IFDEV(ld->dev_allow_localhost, false), ld->config.use_dns,
	    ld->tor_service_password ? ld->tor_service_password : "",
	    ld->config.use_v3_autotor,
	    ld->config.connection_timeout_secs,
	    websocket_helper_path,
	    ld->websocket_port,
	    !deprecated_apis,
	    IFDEV(ld->dev_fast_gossip, false),
	    IFDEV(ld->dev_disconnect_fd >= 0, false),
	    IFDEV(ld->dev_no_ping_timer, false));

	subd_req(ld->connectd, ld->connectd, take(msg), -1, 0,
		 connect_init_done, NULL);

	/* Wait for init_reply */
	io_loop(NULL, NULL);

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
	io_break(connectd);
}

void connectd_activate(struct lightningd *ld)
{
	const u8 *msg = towire_connectd_activate(NULL, ld->listen);

	subd_req(ld->connectd, ld->connectd, take(msg), -1, 0,
		 connect_activate_done, NULL);

	/* Wait for activate_reply */
	io_loop(NULL, NULL);
}

void maybe_disconnect_peer(struct lightningd *ld, struct peer *peer)
{
	struct channel *channel;

	/* Any channels left which want to talk? */
	if (peer->uncommitted_channel)
		return;

	list_for_each(&peer->channels, channel, list) {
		if (!channel->owner)
			continue;
		if (channel->owner->talks_to_peer)
			return;
	}

	/* If shutting down, connectd no longer exists */
	if (!ld->connectd) {
		peer->is_connected = false;
		return;
	}

	subd_send_msg(ld->connectd,
		      take(towire_connectd_discard_peer(NULL, &peer->id)));
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

	if (!param(cmd, buffer, params,
		   p_req("node_id", param_node_id, &dest),
		   p_req("msg", param_bin_from_hex, &msg),
		   NULL))
		return command_param_failed();

	type = fromwire_peektype(msg);
	if (peer_wire_is_defined(type)) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_REQUEST,
		    "Cannot send messages of type %d (%s). It is not possible "
		    "to send messages that have a type managed internally "
		    "since that might cause issues with the internal state "
		    "tracking.",
		    type, peer_wire_name(type));
	}

	if (type % 2 == 0) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_REQUEST,
		    "Cannot send even-typed %d custom message. Currently "
		    "custom messages are limited to odd-numbered message "
		    "types, as even-numbered types might result in "
		    "disconnections.",
		    type);
	}

	peer = peer_by_id(cmd->ld, dest);
	if (!peer) {
		return command_fail(cmd, JSONRPC2_INVALID_REQUEST,
				    "No such peer: %s",
				    type_to_string(cmd, struct node_id, dest));
	}

	if (!peer->is_connected) {
		return command_fail(cmd, JSONRPC2_INVALID_REQUEST,
				    "Peer is not connected: %s",
				    type_to_string(cmd, struct node_id, dest));
	}

	subd_send_msg(cmd->ld->connectd,
		      take(towire_connectd_custommsg_out(cmd, dest, msg)));

	response = json_stream_success(cmd);
	json_add_string(response, "status",
			"Message sent to connectd for delivery");

	return command_success(cmd, response);
}

static const struct json_command sendcustommsg_command = {
    "sendcustommsg",
    "utility",
    json_sendcustommsg,
    "Send a custom message to the peer with the given {node_id}",
    .verbose = "sendcustommsg node_id hexcustommsg",
};

AUTODATA(json_command, &sendcustommsg_command);

#ifdef COMPAT_V0100
#ifdef DEVELOPER
static const struct json_command dev_sendcustommsg_command = {
    "dev-sendcustommsg",
    "utility",
    json_sendcustommsg,
    "Send a custom message to the peer with the given {node_id}",
    .verbose = "dev-sendcustommsg node_id hexcustommsg",
};

AUTODATA(json_command, &dev_sendcustommsg_command);
#endif  /* DEVELOPER */
#endif /* COMPAT_V0100 */

#if DEVELOPER
static struct command_result *json_dev_suppress_gossip(struct command *cmd,
						       const char *buffer,
						       const jsmntok_t *obj UNNEEDED,
						       const jsmntok_t *params)
{
	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	subd_send_msg(cmd->ld->connectd,
		      take(towire_connectd_dev_suppress_gossip(NULL)));

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_suppress_gossip = {
	"dev-suppress-gossip",
	"developer",
	json_dev_suppress_gossip,
	"Stop this node from sending any more gossip."
};
AUTODATA(json_command, &dev_suppress_gossip);
#endif /* DEVELOPER */
