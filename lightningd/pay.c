#include "pay.h"
#include <bitcoin/preimage.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <daemon/chaintopology.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <daemon/sphinx.h>
#include <inttypes.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

/* Outstanding "pay" commands. */
struct pay_command {
	struct list_node list;
	struct sha256 rhash;
	u64 msatoshi;
	const struct pubkey *ids;
	/* Set if this is in progress. */
	struct htlc_end *out;
	/* Preimage if this succeeded. */
	const struct preimage *rval;
	struct command *cmd;
};

static void json_pay_success(struct command *cmd, const struct preimage *rval)
{
	struct json_result *response;

	/* Can be NULL if JSON RPC goes away. */
	if (!cmd)
		return;

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_hex(response, "preimage", rval, sizeof(*rval));
	json_object_end(response);
	command_success(cmd, response);
}

static void json_pay_failed(struct command *cmd,
			    const struct pubkey *sender,
			    enum onion_type failure_code,
			    const char *details)
{
	/* Can be NULL if JSON RPC goes away. */
	if (!cmd)
		return;

	/* FIXME: Report sender! */
	command_fail(cmd, "failed: %s (%s)",
		     onion_type_name(failure_code), details);
}

void payment_succeeded(struct lightningd *ld, struct htlc_end *dst,
		       const struct preimage *rval)
{
	/* FIXME: dev_htlc will do this! */
	if (!dst->pay_command) {
		log_debug(ld->log, "Payment succeeded on HTLC %"PRIu64,
			dst->htlc_id);
		return;
	}

	assert(!dst->pay_command->rval);
	dst->pay_command->rval = tal_dup(dst->pay_command,
					 struct preimage, rval);
	json_pay_success(dst->pay_command->cmd, rval);
	dst->pay_command->out = NULL;
}

/* FIXME: sender is NULL for now: need crypto! */
void payment_failed(struct lightningd *ld, struct htlc_end *dst,
		    const struct pubkey *sender,
		    enum onion_type failure_code)
{
	/* FIXME: dev_htlc will do this! */
	if (!dst->pay_command)
		return;

	/* FIXME: check for routing failure / perm fail. */
	/* check_for_routing_failure(i, sender, failure_code); */
	json_pay_failed(dst->pay_command->cmd, sender, failure_code,
			"reply from remote");
	dst->pay_command->out = NULL;
}

static bool rcvd_htlc_reply(struct subd *subd, const u8 *msg, const int *fds,
			    struct pay_command *pc)
{
	u16 failcode;
	u8 *failstr;

	if (!fromwire_channel_offer_htlc_reply(msg, msg, NULL,
					       &pc->out->htlc_id,
					       &failcode, &failstr)) {
		json_pay_failed(pc->cmd, &subd->ld->dstate.id, -1,
				"daemon bad response");
		return false;
	}

	if (failcode != 0) {
		json_pay_failed(pc->cmd, &subd->ld->dstate.id, failcode,
				"from local daemon");
		return true;
	}

	/* HTLC endpoint now owned by lightningd. */
	tal_steal(subd->ld, pc->out);
	connect_htlc_end(&subd->ld->htlc_ends, pc->out);
	return true;
}

/* When JSON RPC goes away, cmd is freed: detach from any running paycommand */
static void remove_cmd_from_pc(struct command *cmd, struct pay_command *pc)
{
	/* This can be false, in the case where another pay command
	 * re-uses the pc->cmd before we get around to cleaning up. */
	if (pc->cmd == cmd)
		pc->cmd = NULL;
}

static struct pay_command *find_pay_command(struct lightningd *ld,
					    const struct sha256 *rhash)
{
	struct pay_command *pc;

	list_for_each(&ld->dstate.pay_commands, pc, list) {
		if (structeq(rhash, &pc->rhash))
			return pc;
	}
	return NULL;
}

static void pay_command_destroyed(struct pay_command *pc)
{
	list_del(&pc->list);
}

static void json_sendpay(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct pubkey *ids;
	jsmntok_t *routetok, *rhashtok;
	const jsmntok_t *t, *end;
	unsigned int delay, first_delay, base_expiry;
	size_t n_hops;
	struct sha256 rhash;
	struct peer *peer;
	struct pay_command *pc;
	const u8 *onion;
	u8 sessionkey[32];
	struct hoppayload *hoppayloads;
	u64 amount, lastamount;
	struct onionpacket *packet;
	u8 *msg;

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

	/* Expiry for HTLCs is absolute.  And add one to give some margin. */
	base_expiry = get_block_height(cmd->dstate->topology) + 1;

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
		if (!json_tok_number(buffer, delaytok, &delay)) {
			command_fail(cmd, "route %zu invalid delay", n_hops);
			return;
		}
		if (n_hops == 0)
			first_delay = delay;
		else
			hoppayloads[n_hops-1].outgoing_cltv_value
				= base_expiry + delay;
		n_hops++;
	}

	if (n_hops == 0) {
		command_fail(cmd, "Empty route");
		return;
	}

	/* Add payload for final hop */
	tal_resize(&hoppayloads, n_hops);
	memset(&hoppayloads[n_hops-1], 0, sizeof(struct hoppayload));

	pc = find_pay_command(ld, &rhash);
	if (pc) {
		log_debug(ld->log, "json_sendpay: found previous");
		if (pc->out) {
			log_add(ld->log, "... still in progress");
			command_fail(cmd, "still in progress");
			return;
		}
		if (pc->rval) {
			size_t old_nhops = tal_count(pc->ids);
			log_add(ld->log, "... succeeded");
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
		/* FIXME: We can free failed ones... */
		log_add(ld->log, "... retrying");
	}

	peer = peer_by_id(ld, &ids[0]);
	if (!peer) {
		command_fail(cmd, "no connection to first peer found");
		return;
	}

	if (!peer->locked) {
		command_fail(cmd, "first peer channel not locked");
		return;
	}

	if (!peer->owner || !streq(peer->owner->name, "lightningd_channel")) {
		command_fail(cmd, "first peer in %s",
			     peer->owner ? "limbo" : peer->owner->name);
		return;
	}

	randombytes_buf(&sessionkey, sizeof(sessionkey));

	/* Onion will carry us from first peer onwards. */
	packet = create_onionpacket(cmd, ids, hoppayloads, sessionkey,
				    rhash.u.u8, sizeof(struct sha256));
	onion = serialize_onionpacket(cmd, packet);

	if (pc)
		pc->ids = tal_free(pc->ids);
	else {
		pc = tal(ld, struct pay_command);
		list_add_tail(&cmd->dstate->pay_commands, &pc->list);
		tal_add_destructor(pc, pay_command_destroyed);
	}
	pc->cmd = cmd;
	pc->rhash = rhash;
	pc->rval = NULL;
	pc->ids = tal_steal(pc, ids);
	pc->msatoshi = lastamount;

	pc->out = tal(pc, struct htlc_end);
	pc->out->which_end = HTLC_DST;
	pc->out->peer = peer;
	pc->out->msatoshis = amount;
	pc->out->other_end = NULL;
	pc->out->pay_command = pc;

	log_info(ld->log, "Sending %"PRIu64" over %zu hops to deliver %"PRIu64,
		 amount, n_hops, lastamount);
	msg = towire_channel_offer_htlc(pc, amount,
					base_expiry + first_delay,
					&pc->rhash, onion);
	subd_req(pc, peer->owner, take(msg), -1, 0, rcvd_htlc_reply, pc);

	/* Wait until we get response. */
	tal_add_destructor2(cmd, remove_cmd_from_pc, pc);
}

static const struct json_command sendpay_command = {
	"sendpay",
	json_sendpay,
	"Send along {route} in return for preimage of {rhash}",
	"Returns the {preimage} on success"
};
AUTODATA(json_command, &sendpay_command);
