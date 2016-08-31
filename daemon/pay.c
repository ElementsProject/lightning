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
#include <ccan/structeq/structeq.h>
#include <inttypes.h>

/* Outstanding "pay" commands. */
struct pay_command {
	struct list_node list;
	struct sha256 rhash;
	u64 msatoshis, fee;
	struct pubkey id;
	/* Set if this is in progress. */
	struct htlc *htlc;
	/* Preimage if this succeeded. */
	struct rval *rval;
	struct command *cmd;
};

static void json_pay_success(struct command *cmd, const struct rval *rval)
{
	struct json_result *response;

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_hex(response, "preimage", rval, sizeof(*rval));
	json_object_end(response);
	command_success(cmd, response);
}

static void handle_json(struct command *cmd, const struct htlc *htlc)
{
	FailInfo *f;
	struct pubkey id;
	const char *idstr = "INVALID";

	if (htlc->r) {
		json_pay_success(cmd, htlc->r);
		return;
	}

	f = failinfo_unwrap(cmd, htlc->fail, tal_count(htlc->fail));
	if (!f) {
		command_fail(cmd, "failed (bad message)");
		return;
	}

	if (proto_to_pubkey(cmd->dstate->secpctx, f->id, &id))
		idstr = pubkey_to_hexstr(cmd, cmd->dstate->secpctx, &id);

	command_fail(cmd,
		     "failed: error code %u node %s reason %s",
		     f->error_code, idstr, f->reason ? f->reason : "unknown");
}

void complete_pay_command(struct lightningd_state *dstate,
			  const struct htlc *htlc)
{
	struct pay_command *i;

	list_for_each(&dstate->pay_commands, i, list) {
		if (i->htlc == htlc) {
			if (htlc->r)
				i->rval = tal_dup(i, struct rval, htlc->r);
			i->htlc = NULL;

			/* Can be NULL if JSON RPC goes away. */
			if (i->cmd)
				handle_json(i->cmd, htlc);
			return;
		}
	}

	/* Can happen if RPC connection goes away. */
	log_unusual(dstate->base_log, "No command for HTLC %"PRIu64" %s",
		    htlc->id, htlc->r ? "fulfill" : "fail");
}

/* When JSON RPC goes away, cmd is freed: detach from any running paycommand */
static void remove_cmd_from_pc(struct command *cmd)
{
	struct pay_command *pc;

	list_for_each(&cmd->dstate->pay_commands, pc, list) {
		if (pc->cmd == cmd) {
			pc->cmd = NULL;
			return;
		}
	}
	/* We can reach here, in the case where another pay command
	 * re-uses the pc->cmd before we get around to cleaning up. */
}

static struct pay_command *find_pay_command(struct lightningd_state *dstate,
					    const struct sha256 *rhash)
{
	struct pay_command *pc;

	list_for_each(&dstate->pay_commands, pc, list) {
		if (structeq(rhash, &pc->rhash))
			return pc;
	}
	return NULL;
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

	pc = find_pay_command(cmd->dstate, &rhash);
	if (pc) {
		log_debug(cmd->dstate->base_log, "json_pay: found previous");
		if (pc->htlc) {
			log_add(cmd->dstate->base_log, "... still in progress");
			command_fail(cmd, "still in progress");
			return;
		}
		if (pc->rval) {
			log_add(cmd->dstate->base_log, "... succeeded");
			/* Must match successful payment parameters. */
			if (pc->msatoshis != msatoshis) {
				command_fail(cmd,
					     "already succeeded with amount %"
					     PRIu64, pc->msatoshis);
				return;
			}
			if (!structeq(&pc->id, &id)) {
				char *previd;
				previd = pubkey_to_hexstr(cmd,
							  cmd->dstate->secpctx,
							  &pc->id);
				command_fail(cmd,
					     "already succeeded to %s",
					     previd);
				return;
			}
			json_pay_success(cmd, pc->rval);
			return;
		}
		log_add(cmd->dstate->base_log, "... retrying");
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

	if (!pc)
		pc = tal(cmd->dstate, struct pay_command);
	pc->cmd = cmd;
	pc->rhash = rhash;
	pc->rval = NULL;
	pc->id = id;
	pc->msatoshis = msatoshis;
	pc->fee = fee;

	err = command_htlc_add(peer, msatoshis + fee, expiry, &rhash, NULL,
			       onion, &error_code, &pc->htlc);
	if (err) {
		command_fail(cmd, "could not add htlc: %u: %s", error_code, err);
		return;
	}

	/* Wait until we get response. */
	list_add_tail(&cmd->dstate->pay_commands, &pc->list);
	tal_add_destructor(cmd, remove_cmd_from_pc);
}

const struct json_command pay_command = {
	"pay",
	json_pay,
	"Send {id} {msatoshis} in return for preimage of {rhash}",
	"Returns the {preimage} on success"
};
