#include "pay.h"
#include "payalgo.h"
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/routing.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/subd.h>

struct pay {
	struct sha256 payment_hash;
	struct command *cmd;
	u64 msatoshi;
	double maxfeepercent;
};

/* Duplicated here from lightningd/pay.c, but will be modified
 * in a later commit. */
static void
json_sendpay_success(struct command *cmd,
		     const struct preimage *payment_preimage)
{
	struct json_result *response;

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_hex(response, "preimage",
		     payment_preimage, sizeof(*payment_preimage));
	json_object_end(response);
	command_success(cmd, response);
}

/* Duplicated here from lightningd/pay.c, but will be modified
 * in a later commit. */
static void json_sendpay_on_resolve(const struct sendpay_result *r,
				    void *vcmd)
{
	struct command *cmd = (struct command*) vcmd;

	struct json_result *data;
	const char *msg;
	struct routing_failure *fail;

	if (r->succeeded)
		json_sendpay_success(cmd, &r->preimage);
	else {
		switch (r->errorcode) {
		case PAY_IN_PROGRESS:
		case PAY_RHASH_ALREADY_USED:
			data = NULL;
			msg = r->details;
			break;

		case PAY_UNPARSEABLE_ONION:
			data = new_json_result(cmd);
			json_object_start(data, NULL);
			json_add_hex(data, "onionreply",
				     r->onionreply, tal_len(r->onionreply));
			json_object_end(data);

			msg = tal_fmt(cmd,
				      "failed: WIRE_PERMANENT_NODE_FAILURE "
				      "(%s)",
				      r->details);

			break;

		case PAY_DESTINATION_PERM_FAIL:
		case PAY_TRY_OTHER_ROUTE:
			fail = r->routing_failure;
			data = new_json_result(cmd);

			json_object_start(data, NULL);
			json_add_num(data, "erring_index",
				     fail->erring_index);
			json_add_num(data, "failcode",
				     (unsigned) fail->failcode);
			json_add_hex(data, "erring_node",
				     &fail->erring_node,
				     sizeof(fail->erring_node));
			json_add_short_channel_id(data, "erring_channel",
						  &fail->erring_channel);
			if (fail->channel_update)
				json_add_hex(data, "channel_update",
					     fail->channel_update,
					     tal_len(fail->channel_update));
			json_object_end(data);

			msg = tal_fmt(cmd,
				      "failed: %s (%s)",
				      onion_type_name(fail->failcode),
				      r->details);

			break;
		}

		command_fail_detailed(cmd, r->errorcode, data, "%s", msg);
	}
}

static void json_pay_getroute_reply(struct subd *gossip,
				    const u8 *reply, const int *fds,
				    struct pay *pay)
{
	struct route_hop *route;
	u64 msatoshi_sent;
	u64 fee;
	double feepercent;
	struct json_result *data;

	fromwire_gossip_getroute_reply(reply, reply, NULL, &route);

	if (tal_count(route) == 0) {
		command_fail_detailed(pay->cmd, PAY_ROUTE_NOT_FOUND, NULL,
				      "Could not find a route");
		return;
	}

	msatoshi_sent = route[0].amount;
	fee = msatoshi_sent - pay->msatoshi;
	/* FIXME: IEEE Double-precision floating point has only 53 bits
	 * of precision. Total satoshis that can ever be created is
	 * slightly less than 2100000000000000. Total msatoshis that
	 * can ever be created is 1000 times that or
	 * 2100000000000000000, requiring 60.865 bits of precision,
	 * and thus losing precision in the below. Currently, OK, as,
	 * payments are limited to 4294967295 msatoshi. */
	feepercent = ((double) fee) * 100.0 / ((double) pay->msatoshi);
	if (feepercent > pay->maxfeepercent) {
		data = new_json_result(pay);
		json_object_start(data, NULL);
		json_add_u64(data, "fee", fee);
		json_add_double(data, "feepercent", feepercent);
		json_add_u64(data, "msatoshi", pay->msatoshi);
		json_add_double(data, "maxfeepercent", pay->maxfeepercent);
		json_object_end(data);

		command_fail_detailed(pay->cmd, PAY_ROUTE_TOO_EXPENSIVE,
				      data,
				      "Fee %"PRIu64" is %f%% "
				      "of payment %"PRIu64"; "
				      "max fee requested is %f%%",
				      fee, feepercent,
				      pay->msatoshi,
				      pay->maxfeepercent);
		return;
	}

	send_payment(pay->cmd, pay->cmd->ld, &pay->payment_hash, route,
		     &json_sendpay_on_resolve, pay->cmd);
}

static void json_pay(struct command *cmd,
		     const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *bolt11tok, *msatoshitok, *desctok, *riskfactortok, *maxfeetok;
	double riskfactor = 1.0;
	double maxfeepercent = 0.5;
	u64 msatoshi;
	struct pay *pay = tal(cmd, struct pay);
	struct bolt11 *b11;
	char *fail, *b11str, *desc;
	u8 *req;

	if (!json_get_params(cmd, buffer, params,
			     "bolt11", &bolt11tok,
			     "?msatoshi", &msatoshitok,
			     "?description", &desctok,
			     "?riskfactor", &riskfactortok,
			     "?maxfeepercent", &maxfeetok,
			     NULL)) {
		return;
	}

	b11str = tal_strndup(cmd, buffer + bolt11tok->start,
			     bolt11tok->end - bolt11tok->start);
	if (desctok)
		desc = tal_strndup(cmd, buffer + desctok->start,
				   desctok->end - desctok->start);
	else
		desc = NULL;

	b11 = bolt11_decode(pay, b11str, desc, &fail);
	if (!b11) {
		command_fail(cmd, "Invalid bolt11: %s", fail);
		return;
	}

	pay->cmd = cmd;
	pay->payment_hash = b11->payment_hash;

	if (b11->msatoshi) {
		msatoshi = *b11->msatoshi;
		if (msatoshitok) {
			command_fail(cmd, "msatoshi parameter unnecessary");
			return;
		}
	} else {
		if (!msatoshitok) {
			command_fail(cmd, "msatoshi parameter required");
			return;
		}
		if (!json_tok_u64(buffer, msatoshitok, &msatoshi)) {
			command_fail(cmd,
				     "msatoshi '%.*s' is not a valid number",
				     (int)(msatoshitok->end-msatoshitok->start),
				     buffer + msatoshitok->start);
			return;
		}
	}
	pay->msatoshi = msatoshi;

	if (riskfactortok
	    && !json_tok_double(buffer, riskfactortok, &riskfactor)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     (int)(riskfactortok->end - riskfactortok->start),
			     buffer + riskfactortok->start);
		return;
	}

	if (maxfeetok
	    && !json_tok_double(buffer, maxfeetok, &maxfeepercent)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     (int)(maxfeetok->end - maxfeetok->start),
			     buffer + maxfeetok->start);
		return;
	}
	/* Ensure it is in range 0.0 <= maxfeepercent <= 100.0 */
	if (!(0.0 <= maxfeepercent)) {
		command_fail(cmd, "%f maxfeepercent must be non-negative",
			     maxfeepercent);
		return;
	}
	if (!(maxfeepercent <= 100.0)) {
		command_fail(cmd, "%f maxfeepercent must be <= 100.0",
			     maxfeepercent);
		return;
	}
	pay->maxfeepercent = maxfeepercent;

	/* FIXME: use b11->routes */
	req = towire_gossip_getroute_request(cmd, &cmd->ld->id,
					     &b11->receiver_id,
					     msatoshi, riskfactor*1000,
					     b11->min_final_cltv_expiry);
	subd_req(pay, cmd->ld->gossip, req, -1, 0, json_pay_getroute_reply, pay);
	command_still_pending(cmd);
}

static const struct json_command pay_command = {
	"pay",
	json_pay,
	"Send payment specified by {bolt11} with optional {msatoshi} "
	"(if and only if {bolt11} does not have amount), "
	"{description} (required if {bolt11} uses description hash), "
	"{riskfactor} (default 1.0), and "
	"{maxfeepercent} (default 0.5) the maximum acceptable fee as a percentage (e.g. 0.5 => 0.5%)"
};
AUTODATA(json_command, &pay_command);
