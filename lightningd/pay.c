#include "pay.h"
#include <bitcoin/preimage.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <daemon/chaintopology.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <inttypes.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/sphinx.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

/* Outstanding "pay" commands. */
struct pay_command {
	struct list_node list;
	struct sha256 rhash;
	u64 msatoshi;
	const struct pubkey *ids;
	/* Set if this is in progress. */
	struct htlc_out *out;
	/* Preimage if this succeeded. */
	const struct preimage *rval;
	struct command *cmd;

	/* Remember all shared secrets, so we can unwrap an eventual failure */
	struct secret *path_secrets;
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

static void json_pay_failed(struct pay_command *pc,
			    const struct pubkey *sender,
			    enum onion_type failure_code,
			    const char *details)
{
	/* Can be NULL if JSON RPC goes away. */
	if (!pc->cmd)
		return;

	/* FIXME: Report sender! */
	command_fail(pc->cmd, "failed: %s (%s)",
		     onion_type_name(failure_code), details);

	pc->out = NULL;
}

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval)
{
	assert(!hout->pay_command->rval);
	hout->pay_command->rval = tal_dup(hout->pay_command,
					  struct preimage, rval);
	json_pay_success(hout->pay_command->cmd, rval);
	hout->pay_command->out = NULL;
}

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail)
{
	struct pay_command *pc = hout->pay_command;
	enum onion_type failcode;
	struct onionreply *reply;

	/* This gives more details than a generic failure message,
	 * and also the failuremsg here is unencrypted */
	if (localfail) {
		size_t max = tal_len(hout->failuremsg);
		const u8 *p = hout->failuremsg;
		failcode = fromwire_u16(&p, &max);
		json_pay_failed(pc, NULL, failcode, localfail);
		return;
	}

	if (hout->malformed)
		failcode = hout->malformed;
	else {
		reply = unwrap_onionreply(pc, pc->path_secrets,
					  tal_count(pc->path_secrets),
					  hout->failuremsg);
		if (!reply) {
			log_info(hout->key.peer->log,
				 "htlc %"PRIu64" failed with bad reply (%s)",
				 hout->key.id,
				 tal_hex(pc, hout->failuremsg));
			failcode = WIRE_PERMANENT_NODE_FAILURE;
		} else {
			failcode = fromwire_peektype(reply->msg);
			log_info(hout->key.peer->log,
				 "htlc %"PRIu64" failed from %ith node with code 0x%04x (%s)",
				 hout->key.id,
				 reply->origin_index,
				 failcode, onion_type_name(failcode));
		}
	}

	/* FIXME: save ids we can turn reply->origin_index into sender. */

	/* FIXME: check for routing failure / perm fail. */
	/* check_for_routing_failure(i, sender, failure_code); */

	json_pay_failed(pc, NULL, failcode, "reply from remote");
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
	unsigned int delay, base_expiry;
	size_t n_hops;
	struct sha256 rhash;
	struct peer *peer;
	struct pay_command *pc;
	const u8 *onion;
	u8 sessionkey[32];
	struct hop_data *hop_data;
	struct hop_data first_hop_data;
	u64 amount, lastamount;
	struct onionpacket *packet;
	struct secret *path_secrets;
	enum onion_type failcode;

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

	hop_data = tal_arr(cmd, struct hop_data, n_hops);
	for (t = routetok + 1; t < end; t = json_next(t)) {
		const jsmntok_t *amttok, *idtok, *delaytok, *chantok;

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
		chantok = json_get_member(buffer, t, "channel");
		if (!amttok || !idtok || !delaytok || !chantok) {
			command_fail(cmd, "route %zu needs msatoshi/id/channel/delay",
				     n_hops);
			return;
		}

		tal_resize(&hop_data, n_hops + 1);
		tal_resize(&ids, n_hops+1);
		hop_data[n_hops].realm = 0;
		/* What that hop will forward */
		if (!json_tok_u64(buffer, amttok, &amount)) {
			command_fail(cmd, "route %zu invalid msatoshi",
				     n_hops);
			return;
		}
		hop_data[n_hops].amt_forward = amount;

		if (!short_channel_id_from_str(buffer + chantok->start,
					       chantok->end - chantok->start,
					       &hop_data[n_hops].channel_id)) {
			command_fail(cmd, "route %zu invalid id", n_hops);
			return;
		}
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
		hop_data[n_hops].outgoing_cltv = base_expiry + delay;
		n_hops++;
	}

	if (n_hops == 0) {
		command_fail(cmd, "Empty route");
		return;
	}

	/* Store some info we'll need for our own HTLC */
	amount = hop_data[0].amt_forward;
	lastamount = hop_data[n_hops-1].amt_forward;
	first_hop_data = hop_data[0];

	/* Shift the hop_data down by one, so each hop gets its
	 * instructions, not how we got there */
	for (size_t i=0; i < n_hops - 1; i++) {
		hop_data[i] = hop_data[i+1];
	}
	/* And finally set the final hop to the special values in
	 * BOLT04 */
	hop_data[n_hops-1].outgoing_cltv = base_expiry + delay;
	memset(&hop_data[n_hops-1].channel_id, 0, sizeof(struct short_channel_id));

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

	randombytes_buf(&sessionkey, sizeof(sessionkey));

	/* Onion will carry us from first peer onwards. */
	packet = create_onionpacket(cmd, ids, hop_data, sessionkey, rhash.u.u8,
				    sizeof(struct sha256), &path_secrets);
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
	pc->path_secrets = tal_steal(pc, path_secrets);

	log_info(ld->log, "Sending %"PRIu64" over %zu hops to deliver %"PRIu64,
		 amount, n_hops, lastamount);

	/* Wait until we get response. */
	tal_add_destructor2(cmd, remove_cmd_from_pc, pc);

	failcode = send_htlc_out(peer, amount, first_hop_data.outgoing_cltv,
				 &rhash, onion, NULL, pc, &pc->out);
	if (failcode) {
		command_fail(cmd, "first peer not ready: %s",
			     onion_type_name(failcode));
		return;
	}
}

static const struct json_command sendpay_command = {
	"sendpay",
	json_sendpay,
	"Send along {route} in return for preimage of {rhash}",
	"Returns the {preimage} on success"
};
AUTODATA(json_command, &sendpay_command);
