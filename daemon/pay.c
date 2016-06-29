#include "chaintopology.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "onion.h"
#include "pay.h"
#include "peer.h"
#include "routing.h"
#include <ccan/str/hex/hex.h>
#include <inttypes.h>

/* Outstanding "pay" commands. */
struct pay_command {
	struct list_node list;
	struct htlc *htlc;
	struct command *cmd;
};

void complete_pay_command(struct peer *peer,
			  struct htlc *htlc,
			  const struct rval *rval)
{
	struct pay_command *i;

	list_for_each(&peer->pay_commands, i, list) {
		if (i->htlc == htlc) {
			if (rval) {
				struct json_result *response;

				response = new_json_result(i->cmd);	
				json_object_start(response, NULL);
				json_add_hex(response, "preimage",
					     rval->r, sizeof(rval->r));
				json_object_end(response);
				command_success(i->cmd, response);
			} else {
				command_fail(i->cmd, "htlc failed");
			}
			return;
		}
	}
	/* Can happen if RPC connection goes away. */
	log_unusual(peer->log, "No command for HTLC %"PRIu64" %s",
		    htlc->id, rval ? "fulfill" : "fail");
}		

static void remove_from_list(struct pay_command *pc)
{
	list_del(&pc->list);
}

static void json_pay(struct command *cmd,
		     const char *buffer, const jsmntok_t *params)
{
	struct pubkey id;
	jsmntok_t *idtok, *msatoshistok, *rhashtok;
	unsigned int expiry;
	int i;
	u64 msatoshis;
	s64 fee;
	struct sha256 rhash;
	struct node_connection **route;
	struct peer *peer;
	struct pay_command *pc;
	const u8 *onion;

	if (!json_get_params(buffer, params,
			     "id", &idtok,
			     "msatoshis", &msatoshistok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need id, msatoshis and rhash");
		return;
	}

	if (!pubkey_from_hexstr(cmd->dstate->secpctx,
				buffer + idtok->start,
				idtok->end - idtok->start, &id)) {
		command_fail(cmd, "Invalid id");
		return;
	}

	if (!json_tok_u64(buffer, msatoshistok, &msatoshis)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(msatoshistok->end - msatoshistok->start),
			     buffer + msatoshistok->start);
		return;
	}

	if (!hex_decode(buffer + rhashtok->start,
			rhashtok->end - rhashtok->start,
			&rhash, sizeof(rhash))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 hash",
			     (int)(rhashtok->end - rhashtok->start),
			     buffer + rhashtok->start);
		return;
	}

	/* FIXME: Add fee param, check for excessive fee. */
	peer = find_route(cmd->dstate, &id, msatoshis, &fee, &route);
	if (!peer) {
		command_fail(cmd, "no route found");
		return;
	}

	expiry = 0;
	for (i = tal_count(route) - 1; i >= 0; i--) {
		expiry += route[i]->delay;
		if (expiry < route[i]->min_blocks)
			expiry = route[i]->min_blocks;
	}
	expiry += peer->nc->delay;
	if (expiry < peer->nc->min_blocks)
		expiry = peer->nc->min_blocks;

	/* Expiry for HTLCs is absolute.  And add one to give some margin. */
	expiry += get_block_height(cmd->dstate) + 1;

	onion = onion_create(cmd, route, msatoshis, fee);
	pc = tal(cmd, struct pay_command);
	pc->cmd = cmd;
	pc->htlc = command_htlc_add(peer, msatoshis + fee, expiry, &rhash, NULL,
				    onion);
	if (!pc->htlc) {
		command_fail(cmd, "could not add htlc");
		return;
	}

	/* Wait until we get response. */
	list_add_tail(&peer->pay_commands, &pc->list);
	tal_add_destructor(pc, remove_from_list);
}

const struct json_command pay_command = {
	"pay",
	json_pay,
	"Send {id} {msatoshis} in return for preimage of {rhash}",
	"Returns an empty result on success"
};
