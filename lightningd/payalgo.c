#include "pay.h"
#include "payalgo.h"
#include <ccan/isaac/isaac64.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/bolt11.h>
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/routing.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

struct pay {
	/* Parent command. */
	struct command *cmd;

	/* Bolt11 details */
	struct sha256 payment_hash;
	struct pubkey receiver_id;
	struct timeabs expiry;
	u32 min_final_cltv_expiry;

	/* Command details */
	u64 msatoshi;
	double riskfactor;
	double maxfeepercent;

	/* Number of getroute and sendpay tries */
	unsigned int getroute_tries;
	unsigned int sendpay_tries;

	/* Current fuzz we pass into getroute. */
	double fuzz;

	/* Parent of the current pay attempt. This object is
	 * freed, then allocated at the start of each pay
	 * attempt to ensure no leaks across long pay attempts */
	char *try_parent;
};

static void
json_pay_success(struct command *cmd,
		 const struct preimage *payment_preimage,
		 unsigned int getroute_tries,
		 unsigned int sendpay_tries)
{
	struct json_result *response;

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_hex(response, "preimage",
		     payment_preimage, sizeof(*payment_preimage));
	json_add_num(response, "getroute_tries", getroute_tries);
	json_add_num(response, "sendpay_tries", sendpay_tries);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_pay_failure(struct command *cmd,
			     const struct sendpay_result *r)
{
	struct json_result *data = NULL;
	const char *msg = NULL;
	struct routing_failure *fail;

	assert(!r->succeeded);

	/* FIXME: can probably be factored out with similar code
	 * in lightningd/pay.c */
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

	assert(msg);
	command_fail_detailed(cmd, r->errorcode, data, "%s", msg);
}

/* Start a payment attempt. */
static bool json_pay_try(struct pay *pay);

/* Call when sendpay returns to us. */
static void json_pay_sendpay_resolve(const struct sendpay_result *r,
				     void *vpay)
{
	struct pay *pay = (struct pay *) vpay;

	/* If we succeed, hurray */
	if (r->succeeded) {
		json_pay_success(pay->cmd, &r->preimage,
				 pay->getroute_tries, pay->sendpay_tries);
		return;
	}

	/* We can retry only if it is one of the retryable errors
	 * below. If it is not, fail now. */
	if (r->errorcode != PAY_UNPARSEABLE_ONION &&
	    r->errorcode != PAY_TRY_OTHER_ROUTE) {
		json_pay_failure(pay->cmd, r);
		return;
	}

	json_pay_try(pay);
}

static void json_pay_getroute_reply(struct subd *gossip UNUSED,
				    const u8 *reply, const int *fds UNUSED,
				    struct pay *pay)
{
	struct route_hop *route;
	u64 msatoshi_sent;
	u64 fee;
	double feepercent;
	bool fee_too_high;
	struct json_result *data;

	fromwire_gossip_getroute_reply(reply, reply, &route);

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
	fee_too_high = (feepercent > pay->maxfeepercent);
	/* compare fuzz to range */
	if (fee_too_high && pay->fuzz < 0.01) {
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
	if (fee_too_high) {
		/* Retry with lower fuzz */
		pay->fuzz -= 0.15;
		if (pay->fuzz <= 0.0)
			pay->fuzz = 0.0;
		json_pay_try(pay);
		return;
	}

	++pay->sendpay_tries;

	send_payment(pay->try_parent,
		     pay->cmd->ld, &pay->payment_hash, route,
		     &json_pay_sendpay_resolve, pay);
}

/* Start a payment attempt. Return true if deferred,
 * false if resolved now. */
static bool json_pay_try(struct pay *pay)
{
	u8 *seed;
	u8 *req;
	struct command *cmd = pay->cmd;
	struct timeabs now = time_now();
	struct json_result *data;

	/* If too late anyway, fail now. */
	if (time_after(now, pay->expiry)) {
		data = new_json_result(cmd);
		json_object_start(data, NULL);
		json_add_num(data, "now", now.ts.tv_sec);
		json_add_num(data, "expiry", pay->expiry.ts.tv_sec);
		json_object_end(data);
		command_fail_detailed(cmd, PAY_INVOICE_EXPIRED, data,
				      "Invoice expired");
		return false;
	}

	/* Clear previous try memory. */
	pay->try_parent = tal_free(pay->try_parent);
	pay->try_parent = tal(pay, char);

	/* Generate random seed */
	seed = tal_arr(pay->try_parent, u8, ISAAC64_SEED_SZ_MAX);
	randombytes_buf(seed, tal_len(seed));

	++pay->getroute_tries;

	/* FIXME: use b11->routes */
	req = towire_gossip_getroute_request(pay->try_parent,
					     &cmd->ld->id,
					     &pay->receiver_id,
					     pay->msatoshi,
					     pay->riskfactor,
					     pay->min_final_cltv_expiry,
					     &pay->fuzz,
					     seed);
	subd_req(pay->try_parent, cmd->ld->gossip, req, -1, 0, json_pay_getroute_reply, pay);

	return true;
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
	pay->receiver_id = b11->receiver_id;
	memset(&pay->expiry, 0, sizeof(pay->expiry));
	pay->expiry.ts.tv_sec = b11->timestamp + b11->expiry;
	pay->min_final_cltv_expiry = b11->min_final_cltv_expiry;

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
				     msatoshitok->end-msatoshitok->start,
				     buffer + msatoshitok->start);
			return;
		}
	}
	pay->msatoshi = msatoshi;

	if (riskfactortok
	    && !json_tok_double(buffer, riskfactortok, &riskfactor)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     riskfactortok->end - riskfactortok->start,
			     buffer + riskfactortok->start);
		return;
	}
	pay->riskfactor = riskfactor * 1000;

	if (maxfeetok
	    && !json_tok_double(buffer, maxfeetok, &maxfeepercent)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     maxfeetok->end - maxfeetok->start,
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

	pay->getroute_tries = 0;
	pay->sendpay_tries = 0;
	pay->fuzz = 0.75;
	pay->try_parent = NULL;

	/* Initiate payment */
	if (json_pay_try(pay))
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
