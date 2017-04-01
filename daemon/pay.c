#include "chaintopology.h"
#include "db.h"
#include "failure.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "pay.h"
#include "peer.h"
#include "peer_internal.h"
#include "routing.h"
#include "sphinx.h"
#include <bitcoin/preimage.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <inttypes.h>
#include <sodium/randombytes.h>

/* Outstanding "pay" commands. */
struct pay_command {
	struct list_node list;
	struct sha256 rhash;
	u64 msatoshi;
	const struct pubkey *ids;
	/* Set if this is in progress. */
	struct htlc *htlc;
	/* Preimage if this succeeded. */
	const struct preimage *rval;
	struct command *cmd;
};
static void json_pay_success(struct command *cmd, const struct preimage *rval)
{
	struct json_result *response;

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_hex(response, "preimage", rval, sizeof(*rval));
	json_object_end(response);
	command_success(cmd, response);
}

static void handle_json(struct command *cmd, const struct htlc *htlc,
			const FailInfo *f)
{
	struct pubkey id;
	const char *idstr = "INVALID";

	if (htlc->r) {
		json_pay_success(cmd, htlc->r);
		return;
	}

	if (!f) {
		command_fail(cmd, "failed (bad message)");
		return;
	}

	if (proto_to_pubkey(f->id, &id))
		idstr = pubkey_to_hexstr(cmd, &id);

	command_fail(cmd,
		     "failed: error code %u node %s reason %s",
		     f->error_code, idstr, f->reason ? f->reason : "unknown");
}

static void check_routing_failure(struct lightningd_state *dstate,
				  const struct pay_command *pc,
				  const FailInfo *f)
{
	size_t i;
	struct pubkey id;

	if (!f)
		return;

	/* FIXME: We remove route on *any* failure. */
	log_debug(dstate->base_log, "Seeking route for fail code %u",
		  f->error_code);
	if (!proto_to_pubkey(f->id, &id)) {
		log_add(dstate->base_log, " - bad node");
		return;
	}

	log_add_struct(dstate->base_log, " node %s", struct pubkey, &id);

	/* Don't remove route if it's last node (obviously) */
	for (i = 0; i+1 < tal_count(pc->ids); i++) {
		if (structeq(&pc->ids[i], &id)) {
			remove_connection(dstate->rstate, &pc->ids[i], &pc->ids[i+1]);
			return;
		}
	}

	if (structeq(&pc->ids[i], &id))
		log_debug(dstate->base_log, "Final node: ignoring");
	else
		log_debug(dstate->base_log, "Node not on route: ignoring");
}

void complete_pay_command(struct lightningd_state *dstate,
			  const struct htlc *htlc)
{
	struct pay_command *i;

	list_for_each(&dstate->pay_commands, i, list) {
		if (i->htlc == htlc) {
			FailInfo *f = NULL;

			db_complete_pay_command(dstate, htlc);

			if (htlc->r)
				i->rval = tal_dup(i, struct preimage, htlc->r);
			else {
				f = failinfo_unwrap(i->cmd, htlc->fail,
						    tal_count(htlc->fail));
				check_routing_failure(dstate, i, f);
			}

			/* No longer connected to live HTLC. */
			i->htlc = NULL;

			/* Can be NULL if JSON RPC goes away. */
			if (i->cmd)
				handle_json(i->cmd, htlc, f);
			return;
		}
	}

	/* Can happen with testing low-level commands. */
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

/* For database restore. */
bool pay_add(struct lightningd_state *dstate,
	     const struct sha256 *rhash,
	     u64 msatoshi,
	     const struct pubkey *ids,
	     struct htlc *htlc,
	     const u8 *fail UNNEEDED,
	     const struct preimage *r)
{
	struct pay_command *pc;

	if (find_pay_command(dstate, rhash))
		return false;

	pc = tal(dstate, struct pay_command);
	pc->rhash = *rhash;
	pc->msatoshi = msatoshi;
	pc->ids = tal_dup_arr(pc, struct pubkey, ids, tal_count(ids), 0);
	pc->htlc = htlc;
	if (r)
		pc->rval = tal_dup(pc, struct preimage, r);
	else
		pc->rval = NULL;
	pc->cmd = NULL;

	list_add_tail(&dstate->pay_commands, &pc->list);
	return true;
}

static void json_add_route(struct json_result *response,
			   const struct pubkey *id,
			   u64 amount, unsigned int delay)
{
	json_object_start(response, NULL);
	json_add_pubkey(response, "id", id);
	json_add_u64(response, "msatoshi", amount);
	json_add_num(response, "delay", delay);
	json_object_end(response);
}

static void json_getroute(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct pubkey id;
	jsmntok_t *idtok, *msatoshitok, *riskfactortok;
	struct json_result *response;
	size_t i;
	u64 msatoshi;
	double riskfactor;

	if (!json_get_params(buffer, params,
			     "id", &idtok,
			     "msatoshi", &msatoshitok,
			     "riskfactor", &riskfactortok,
			     NULL)) {
		command_fail(cmd, "Need id, msatoshi and riskfactor");
		return;
	}

	if (!pubkey_from_hexstr(buffer + idtok->start,
				idtok->end - idtok->start, &id)) {
		command_fail(cmd, "Invalid id");
		return;
	}

	if (!json_tok_u64(buffer, msatoshitok, &msatoshi)) {
		command_fail(cmd, "'%.*s' is not a valid number",
			     (int)(msatoshitok->end - msatoshitok->start),
			     buffer + msatoshitok->start);
		return;
	}

	if (!json_tok_double(buffer, riskfactortok, &riskfactor)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     (int)(riskfactortok->end - riskfactortok->start),
			     buffer + riskfactortok->start);
		return;
	}

	struct route_hop *hops = get_route(cmd, cmd->dstate->rstate, &cmd->dstate->id, &id, msatoshi, riskfactor);

	if (!hops) {
		command_fail(cmd, "no route found");
		return;
	}

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_array_start(response, "route");
	for (i = 0; i < tal_count(hops); i++)
		json_add_route(response,
			       &hops[i].nodeid, hops[i].amount, hops[i].delay);
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command getroute_command = {
	"getroute",
	json_getroute,
	"Return route to {id} for {msatoshi}, using {riskfactor}",
	"Returns a {route} array of {id} {msatoshi} {delay}: msatoshi and delay (in blocks) is cumulative."
};
AUTODATA(json_command, &getroute_command);

static void json_sendpay(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct pubkey *ids;
	jsmntok_t *routetok, *rhashtok;
	const jsmntok_t *t, *end;
	unsigned int delay;
	size_t n_hops;
	struct sha256 rhash;
	struct peer *peer;
	struct pay_command *pc;
	bool replacing = false;
	const u8 *onion;
	u8 sessionkey[32];
	enum fail_error error_code;
	const char *err;
	struct hoppayload *hoppayloads;
	u64 amount, lastamount;
	struct onionpacket *packet;

	if (!json_get_params(buffer, params,
			     "route", &routetok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need route and rhash");
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

	if (routetok->type != JSMN_ARRAY) {
		command_fail(cmd, "'%.*s' is not an array",
			     (int)(routetok->end - routetok->start),
			     buffer + routetok->start);
		return;
	}

	end = json_next(routetok);
	n_hops = 0;
	ids = tal_arr(cmd, struct pubkey, n_hops);
	hoppayloads = tal_arr(cmd, struct hoppayload, 0);
	for (t = routetok + 1; t < end; t = json_next(t)) {
		const jsmntok_t *amttok, *idtok, *delaytok;

		if (t->type != JSMN_OBJECT) {
			command_fail(cmd, "route %zu '%.*s' is not an object",
				     n_hops,
				     (int)(t->end - t->start),
				     buffer + t->start);
			return;
		}
		amttok = json_get_member(buffer, t, "msatoshi");
		idtok = json_get_member(buffer, t, "id");
		delaytok = json_get_member(buffer, t, "delay");
		if (!amttok || !idtok || !delaytok) {
			command_fail(cmd, "route %zu needs msatoshi/id/delay",
				     n_hops);
			return;
		}

		if (n_hops == 0) {
			/* What we will send */
			if (!json_tok_u64(buffer, amttok, &amount)) {
				command_fail(cmd, "route %zu invalid msatoshi", n_hops);
				return;
			}
			lastamount = amount;
		} else{
			/* What that hop will forward */
			tal_resize(&hoppayloads, n_hops);
			memset(&hoppayloads[n_hops-1], 0, sizeof(struct hoppayload));
			if (!json_tok_u64(buffer, amttok, &hoppayloads[n_hops-1].amt_to_forward)) {
				command_fail(cmd, "route %zu invalid msatoshi", n_hops);
				return;
			}
			/* FIXME: Populate outgoing_cltv_value */
			lastamount = hoppayloads[n_hops-1].amt_to_forward;
		}

		tal_resize(&ids, n_hops+1);
		memset(&ids[n_hops], 0, sizeof(ids[n_hops]));
		if (!pubkey_from_hexstr(buffer + idtok->start,
					idtok->end - idtok->start,
					&ids[n_hops])) {
			command_fail(cmd, "route %zu invalid id", n_hops);
			return;
		}
		/* Only need first delay. */
		if (n_hops == 0 && !json_tok_number(buffer, delaytok, &delay)) {
			command_fail(cmd, "route %zu invalid delay", n_hops);
			return;
		}
		n_hops++;
	}

	/* Add payload for final hop */
	tal_resize(&hoppayloads, n_hops);
	memset(&hoppayloads[n_hops-1], 0, sizeof(struct hoppayload));

	if (n_hops == 0) {
		command_fail(cmd, "Empty route");
		return;
	}

	pc = find_pay_command(cmd->dstate, &rhash);
	if (pc) {
		replacing = true;
		log_debug(cmd->dstate->base_log, "json_sendpay: found previous");
		if (pc->htlc) {
			log_add(cmd->dstate->base_log, "... still in progress");
			command_fail(cmd, "still in progress");
			return;
		}
		if (pc->rval) {
			size_t old_nhops = tal_count(pc->ids);
			log_add(cmd->dstate->base_log, "... succeeded");
			/* Must match successful payment parameters. */
			if (pc->msatoshi != lastamount) {
				command_fail(cmd,
					     "already succeeded with amount %"
					     PRIu64, pc->msatoshi);
				return;
			}
			if (!structeq(&pc->ids[old_nhops-1], &ids[n_hops-1])) {
				char *previd;
				previd = pubkey_to_hexstr(cmd,
							  &pc->ids[old_nhops-1]);
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

	peer = find_peer(cmd->dstate, &ids[0]);
	if (!peer) {
		command_fail(cmd, "no connection to first peer found");
		return;
	}

	randombytes_buf(&sessionkey, sizeof(sessionkey));

	/* Onion will carry us from first peer onwards. */
	packet = create_onionpacket(cmd, ids, hoppayloads, sessionkey,
				    rhash.u.u8, sizeof(struct sha256));
	onion = serialize_onionpacket(cmd, packet);

	if (pc)
		pc->ids = tal_free(pc->ids);
	else
		pc = tal(cmd->dstate, struct pay_command);
	pc->cmd = cmd;
	pc->rhash = rhash;
	pc->rval = NULL;
	pc->ids = tal_steal(pc, ids);
	pc->msatoshi = lastamount;

	/* Expiry for HTLCs is absolute.  And add one to give some margin. */
	err = command_htlc_add(peer, amount,
			       delay + get_block_height(cmd->dstate->topology)
			       + 1,
			       &rhash, NULL,
			       onion, &error_code, &pc->htlc);
	if (err) {
		command_fail(cmd, "could not add htlc: %u: %s", error_code, err);
		tal_free(pc);
		return;
	}

	if (replacing) {
		if (!db_replace_pay_command(cmd->dstate, &pc->rhash,
					    pc->ids, pc->msatoshi,
					    pc->htlc)) {
			command_fail(cmd, "database error");
			/* We could reconnect, but db error is *bad*. */
			peer_fail(peer, __func__);
			tal_free(pc);
			return;
		}
	} else {
		if (!db_new_pay_command(cmd->dstate, &pc->rhash,
					pc->ids, pc->msatoshi,
					pc->htlc)) {
			command_fail(cmd, "database error");
			/* We could reconnect, but db error is *bad*. */
			peer_fail(peer, __func__);
			tal_free(pc);
			return;
		}
	}

	/* Wait until we get response. */
	list_add_tail(&cmd->dstate->pay_commands, &pc->list);
	tal_add_destructor(cmd, remove_cmd_from_pc);
}

static const struct json_command sendpay_command = {
	"sendpay",
	json_sendpay,
	"Send along {route} in return for preimage of {rhash}",
	"Returns the {preimage} on success"
};
AUTODATA(json_command, &sendpay_command);
