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
	list_add_tail(&ld->connects, &c->list);
	tal_add_destructor(c, destroy_connect);
	return c;
}

/* Finds first command which matches. */
static struct connect *find_connect(struct lightningd *ld,
				    const struct pubkey *id)
{
	struct connect *i;

	list_for_each(&ld->connects, i, list) {
		if (pubkey_eq(&i->id, id))
			return i;
	}
	return NULL;
}

void gossip_connect_result(struct lightningd *ld, const u8 *msg)
{
	struct pubkey id;
	bool connected;
	char *err;
	struct connect *c;

	if (!fromwire_gossipctl_connect_to_peer_result(tmpctx, msg,
						       &id,
						       &connected,
						       &err))
		fatal("Gossip gave bad GOSSIPCTL_CONNECT_TO_PEER_RESULT message %s",
		      tal_hex(msg, msg));


	/* We can have multiple connect commands: complete them all */
	while ((c = find_connect(ld, &id)) != NULL) {
		if (connected) {
			struct json_result *response = new_json_result(c->cmd);
			json_object_start(response, NULL);
			json_add_pubkey(response, "id", &id);
			json_object_end(response);
			command_success(c->cmd, response);
		} else {
			command_fail(c->cmd, "%s", err);
		}
		/* They delete themselves from list */
	}
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
	struct wireaddr_internal addr;
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
		u32 port;
		/* Is there a port? */
		if (porttok) {
			if (!json_tok_number(buffer, porttok, &port) || !port) {
				command_fail(cmd, "Port %.*s not valid",
					     porttok->end - porttok->start,
					     buffer + porttok->start);
				return;
			}
		} else {
			port = DEFAULT_PORT;
		}
		if (!parse_wireaddr_internal(name, &addr, port, false,
					     &err_msg)) {
			command_fail(cmd, "Host %s:%u not valid: %s",
				     name, port, err_msg ? err_msg : "port is 0");
			return;
		}

		/* Tell it about the address. */
		msg = towire_gossipctl_peer_addrhint(cmd, &id, &addr);
		subd_send_msg(cmd->ld->gossip, take(msg));
	}

	/* If there isn't already a connect command, tell gossipd */
	if (!find_connect(cmd->ld, &id)) {
		msg = towire_gossipctl_connect_to_peer(NULL, &id);
		subd_send_msg(cmd->ld->gossip, take(msg));
	}
	/* Leave this here for gossip_connect_result */
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
