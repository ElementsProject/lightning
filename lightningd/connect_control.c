#include <bitcoin/pubkey.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/wireaddr.h>
#include <gossipd/gen_gossip_wire.h>
#include <lightningd/connect_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/subd.h>

struct connect {
	struct list_node list;
	struct pubkey id;
	struct command *cmd;
};

static void destroy_connect(struct connect *c)
{
	list_del(&c->list);
}

static struct connect *new_connect(struct lightningd *ld,
				   const struct pubkey *id,
				   struct command *cmd)
{
	struct connect *c = tal(cmd, struct connect);
	c->id = *id;
	c->cmd = cmd;
	list_add(&ld->connects, &c->list);
	tal_add_destructor(c, destroy_connect);
	return c;
}

void connect_succeeded(struct lightningd *ld, const struct pubkey *id)
{
	struct connect *i, *next;

	/* Careful!  Completing command frees connect. */
	list_for_each_safe(&ld->connects, i, next, list) {
		struct json_result *response;

		if (!pubkey_eq(&i->id, id))
			continue;

		response = new_json_result(i->cmd);
		json_object_start(response, NULL);
		json_add_pubkey(response, "id", id);
		json_object_end(response);
		command_success(i->cmd, response);
	}
}

void connect_failed(struct lightningd *ld, const struct pubkey *id,
		    const char *error)
{
	struct connect *i, *next;

	/* Careful!  Completing command frees connect. */
	list_for_each_safe(&ld->connects, i, next, list) {
		if (pubkey_eq(&i->id, id))
			command_fail(i->cmd, "%s", error);
	}
}

void peer_connection_failed(struct lightningd *ld, const u8 *msg)
{
	struct pubkey id;
	u32 attempts, timediff;
	bool addr_unknown;
	char *error;

	if (!fromwire_gossip_peer_connection_failed(msg, &id, &timediff,
						    &attempts, &addr_unknown))
		fatal(
		    "Gossip gave bad GOSSIP_PEER_CONNECTION_FAILED message %s",
		    tal_hex(msg, msg));

	if (addr_unknown) {
		error = tal_fmt(
		    msg, "No address known for node %s, please provide one",
		    type_to_string(msg, struct pubkey, &id));
	} else {
		error = tal_fmt(msg, "Could not connect to %s after %d seconds and %d attempts",
				type_to_string(msg, struct pubkey, &id), timediff,
				attempts);
	}

	connect_failed(ld, &id, error);
}

/* Gossipd tells us peer was already connected. */
void peer_already_connected(struct lightningd *ld, const u8 *msg)
{
	struct pubkey id;

	if (!fromwire_gossip_peer_already_connected(msg, &id))
		fatal("Gossip gave bad GOSSIP_PEER_ALREADY_CONNECTED message %s",
		      tal_hex(msg, msg));

	/* If we were waiting for connection, we succeeded. */
	connect_succeeded(ld, &id);
}

static void json_connect(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *hosttok, *porttok, *idtok;
	struct pubkey id;
	char *id_str;
	char *atptr;
	char *ataddr = NULL;
	const char *name;
	struct wireaddr addr;
	u8 *msg;
	const char *err_msg;

	if (!json_get_params(cmd, buffer, params,
			     "id", &idtok,
			     "?host", &hosttok,
			     "?port", &porttok,
			     NULL)) {
		return;
	}

	/* Check for id@addrport form */
	id_str = tal_strndup(cmd, buffer + idtok->start,
			     idtok->end - idtok->start);
	atptr = strchr(id_str, '@');
	if (atptr) {
		int atidx = atptr - id_str;
		ataddr = tal_strdup(cmd, atptr + 1);
		/* Cut id. */
		idtok->end = idtok->start + atidx;
	}

	if (!json_tok_pubkey(buffer, idtok, &id)) {
		command_fail(cmd, "id %.*s not valid",
			     idtok->end - idtok->start,
			     buffer + idtok->start);
		return;
	}

	if (hosttok && ataddr) {
		command_fail(cmd,
			     "Can't specify host as both xxx@yyy "
			     "and separate argument");
		return;
	}

	/* Get parseable host if provided somehow */
	if (hosttok)
		name = tal_strndup(cmd, buffer + hosttok->start,
				   hosttok->end - hosttok->start);
	else if (ataddr)
		name = ataddr;
	else
		name = NULL;

	/* Port without host name? */
	if (porttok && !name) {
		command_fail(cmd, "Can't specify port without host");
		return;
	}

	/* Was there parseable host name? */
	if (name) {
		/* Is there a port? */
		if (porttok) {
			u32 port;
			if (!json_tok_number(buffer, porttok, &port)) {
				command_fail(cmd, "Port %.*s not valid",
					     porttok->end - porttok->start,
					     buffer + porttok->start);
				return;
			}
			addr.port = port;
		} else {
			addr.port = DEFAULT_PORT;
		}
		if (!parse_wireaddr(name, &addr, addr.port, &err_msg) || !addr.port) {
			command_fail(cmd, "Host %s:%u not valid: %s",
				     name, addr.port, err_msg ? err_msg : "port is 0");
			return;
		}

		/* Tell it about the address. */
		msg = towire_gossipctl_peer_addrhint(cmd, &id, &addr);
		subd_send_msg(cmd->ld->gossip, take(msg));
	}

	/* Now tell it to try reaching it. */
	msg = towire_gossipctl_reach_peer(cmd, &id);
	subd_send_msg(cmd->ld->gossip, take(msg));

	/* Leave this here for gossip_peer_connected */
	new_connect(cmd->ld, &id, cmd);
	command_still_pending(cmd);
}

static const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to {id} at {host} (which can end in ':port' if not default). "
	"{id} can also be of the form id@host"
};
AUTODATA(json_command, &connect_command);
