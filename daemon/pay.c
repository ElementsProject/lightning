#include "chaintopology.h"
#include "failure.h"
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

void complete_pay_command(struct peer *peer, struct htlc *htlc)
{
	struct pay_command *i;

	list_for_each(&peer->pay_commands, i, list) {
		if (i->htlc == htlc) {
			if (htlc->r) {
				struct json_result *response;

				response = new_json_result(i->cmd);	
				json_object_start(response, NULL);
				json_add_hex(response, "preimage",
					     htlc->r, sizeof(*htlc->r));
				json_object_end(response);
				command_success(i->cmd, response);
			} else {
				FailInfo *f;
				f = failinfo_unwrap(i->cmd, htlc->fail,
						    tal_count(htlc->fail));
				if (!f) {
					command_fail(i->cmd,
						     "htlc failed (bad message)");
				} else {
					struct pubkey id;
					secp256k1_context *secpctx;
					const char *idstr = "INVALID";

					secpctx = i->cmd->dstate->secpctx;
					if (proto_to_pubkey(secpctx,
							    f->id, &id))
						idstr = pubkey_to_hexstr(i->cmd,
							 secpctx, &id);
					command_fail(i->cmd,
						     "htlc failed: error code %u"
						     " node %s, reason %s",
						     f->error_code, idstr,
						     f->reason ? f->reason
						     : "unknown");
				}
			}
			return;
		}
	}

	/* Can happen if RPC connection goes away. */
	log_unusual(peer->log, "No command for HTLC %"PRIu64" %s",
		    htlc->id, htlc->r ? "fulfill" : "fail");
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
	enum fail_error error_code;
	const char *err;

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

	onion = onion_create(cmd, cmd->dstate->secpctx, route, msatoshis, fee);
	pc = tal(cmd, struct pay_command);
	pc->cmd = cmd;
	err = command_htlc_add(peer, msatoshis + fee, expiry, &rhash, NULL,
			       onion, &error_code, &pc->htlc);
	if (err) {
		command_fail(cmd, "could not add htlc: %u: %s", error_code, err);
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
