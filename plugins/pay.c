#include <ccan/array_size/array_size.h>
#include <ccan/intmap/intmap.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/bolt11.h>
#include <common/type_to_string.h>
#include <plugins/libplugin.h>

struct pay_attempt {
	const char *route;
	const char *failure;
};

struct pay_command {
	/* Destination, as text */
	const char *dest;

	/* How much we're paying, and what riskfactor for routing. */
	u64 msatoshi;
	double riskfactor;

	/* Limits on what routes we'll accept. */
	double maxfeepercent;
	unsigned int maxdelay;
	u64 exemptfee;

	/* Payment hash, as text. */
	const char *payment_hash;

	/* Description, if any. */
	const char *desc;

	/* Chatty description of attempts. */
	struct pay_attempt *attempts;

	/* Time to stop retrying. */
	struct timeabs stoptime;

	/* Channels which have failed us. */
	const char **excludes;
};

static struct command_result *start_pay_attempt(struct command *cmd,
						struct pay_command *pc);

static struct command_result *waitsendpay_expired(struct command *cmd,
						  struct pay_command *pc)
{
	char *errmsg, *data;

	errmsg = tal_fmt(pc, "Gave up after %zu attempts",
			 tal_count(pc->attempts));
	data = tal_strdup(pc, "'attempts': [ ");
	for (size_t i = 0; i < tal_count(pc->attempts); i++)
		tal_append_fmt(&data, "%s { 'route': %s,\n 'failure': '%s'\n }",
			       i == 0 ? "" : ",",
			       pc->attempts[i].route,
			       pc->attempts[i].failure);
	tal_append_fmt(&data, "]");
	return command_done_err(cmd, PAY_STOPPED_RETRYING, errmsg, data);
}

static struct command_result *waitsendpay_error(struct command *cmd,
						const char *buf,
						const jsmntok_t *error,
						struct pay_command *pc)
{
	struct pay_attempt *attempt;
	const jsmntok_t *codetok, *scidtok, *dirtok;
	int code;

	codetok = json_get_member(buf, error, "code");
	if (!json_to_int(buf, codetok, &code))
		plugin_err("waitsendpay error gave no 'code'? '%.*s'",
			   error->end - error->start, buf + error->start);

	/* FIXME: Handle PAY_UNPARSEABLE_ONION! */

	/* Many error codes are final. */
	if (code != PAY_TRY_OTHER_ROUTE) {
		return forward_error(cmd, buf, error, pc);
	}

	scidtok = json_delve(buf, error, ".data.erring_channel");
	if (!scidtok)
		plugin_err("waitsendpay error no erring_channel '%.*s'",
			   error->end - error->start, buf + error->start);
	dirtok = json_delve(buf, error, ".data.erring_direction");
	if (!dirtok)
		plugin_err("waitsendpay error no erring_direction '%.*s'",
			   error->end - error->start, buf + error->start);

	/* Add erring channel to exclusion list. */
	tal_arr_expand(&pc->excludes, tal_fmt(pc->excludes, "%.*s/%c",
					      scidtok->end - scidtok->start,
					      buf + scidtok->start,
					      buf[dirtok->start]));

	attempt = &pc->attempts[tal_count(pc->attempts)-1];
	attempt->failure = json_strdup(pc->attempts, buf, error);

	if (time_after(time_now(), pc->stoptime)) {
		return waitsendpay_expired(cmd, pc);
	}

	/* Try again. */
	return start_pay_attempt(cmd, pc);
}

static struct command_result *sendpay_done(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *result,
					   struct pay_command *pc)
{
	return send_outreq(cmd, "waitsendpay",
			   forward_result, waitsendpay_error, pc,
			   "'payment_hash': '%s', 'timeout': 60",
			   pc->payment_hash);
}

static struct command_result *getroute_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct pay_command *pc)
{
	struct pay_attempt attempt;
	const jsmntok_t *t = json_get_member(buf, result, "route");
	char *json_desc;
	u64 fee;
	u32 delay;
	double feepercent;

	if (!t)
		plugin_err("getroute gave no 'route'? '%.*s'",
			   result->end - result->start, buf);

	if (!json_to_u64(buf, json_delve(buf, t, "[0].msatoshi"), &fee))
		plugin_err("getroute with invalid msatoshi? '%.*s'",
			   result->end - result->start, buf);
	fee -= pc->msatoshi;

	if (!json_to_number(buf, json_delve(buf, t, "[0].delay"), &delay))
		plugin_err("getroute with invalid delay? '%.*s'",
			   result->end - result->start, buf);

	/* Casting u64 to double will lose some precision. The loss of precision
	 * in feepercent will be like 3.0000..(some dots)..1 % - 3.0 %.
	 * That loss will not be representable in double. So, it's Okay to
	 * cast u64 to double for feepercent calculation. */
	feepercent = ((double)fee) * 100.0 / ((double) pc->msatoshi);

	if (fee > pc->exemptfee && feepercent > pc->maxfeepercent) {
		return command_fail(cmd, PAY_ROUTE_TOO_EXPENSIVE,
				    "Route wanted fee of %"PRIu64" msatoshis",
				    fee);
	}

	if (delay > pc->maxdelay) {
		return command_fail(cmd, PAY_ROUTE_TOO_EXPENSIVE,
				    "Route wanted delay of %u blocks", delay);
	}

	attempt.route = json_strdup(pc->attempts, buf, result);
	tal_arr_expand(&pc->attempts, attempt);

	if (pc->desc)
		json_desc = tal_fmt(pc, ", 'description': '%s'", pc->desc);
	else
		json_desc = "";

	return send_outreq(cmd, "sendpay", sendpay_done, forward_error, pc,
			   "'route': %.*s, 'payment_hash': '%s'%s",
			   t->end - t->start, buf + t->start,
			   pc->payment_hash,
			   json_desc);
}

static struct command_result *start_pay_attempt(struct command *cmd,
						struct pay_command *pc)
{
	char *exclude;

	if (tal_count(pc->excludes) != 0) {
		exclude = tal_strdup(tmpctx, ",'exclude': [");
		for (size_t i = 0; i < tal_count(pc->excludes); i++)
			/* JSON.org grammar doesn't allow trailing , */
			tal_append_fmt(&exclude, "%s %s",
				       i == 0 ? "" : ",",
				       pc->excludes[i]);
		tal_append_fmt(&exclude, "]");
	} else
		exclude = "";

	/* OK, ask for route to destination */
	return send_outreq(cmd, "getroute", getroute_done, forward_error, pc,
			   "'id': '%s',"
			   "'msatoshi': %"PRIu64","
			   "'riskfactor': %f%s",
			   pc->dest, pc->msatoshi, pc->riskfactor, exclude);
}

/* gossipd doesn't know much about the current state of channels; here we
 * manually exclude peers which are disconnected and channels which lack
 * current capacity (it will eliminate those without total capacity). */
static struct command_result *listpeers_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct pay_command *pc)
{
	const jsmntok_t *peer, *peers_end;

	peer = json_get_member(buf, result, "peers");
	if (!peer)
		plugin_err("listpeers gave no 'peers'? '%.*s'",
			   result->end - result->start, buf);

	peers_end = json_next(peer);
	for (peer = peer + 1; peer < peers_end; peer = json_next(peer)) {
		const jsmntok_t *chan, *chans_end;
		bool connected;

		json_to_bool(buf, json_get_member(buf, peer, "connected"),
			     &connected);
		chan = json_get_member(buf, peer, "channels");
		chans_end = json_next(chan);
		for (chan = chan + 1; chan < chans_end; chan = json_next(chan)) {
			const jsmntok_t *state, *spendable, *scid, *dir;
			u64 capacity;

			/* gossipd will only consider things in state NORMAL
			 * anyway; we don't need to exclude others. */
			state = json_get_member(buf, chan, "state");
			if (!json_tok_streq(buf, state, "CHANNELD_NORMAL"))
				continue;

			spendable = json_get_member(buf, chan,
						    "spendable_msatoshi");
			json_to_u64(buf, spendable, &capacity);

			if (connected && capacity >= pc->msatoshi)
				continue;

			/* Exclude this disconnected or low-capacity channel */
			scid = json_get_member(buf, chan, "short_channel_id");
			dir = json_get_member(buf, chan, "direction");
			tal_arr_expand(&pc->excludes,
				       tal_fmt(pc->excludes, "%.*s/%c",
					       scid->end - scid->start,
					       buf + scid->start,
					       buf[dir->start]));
		}
	}

	return start_pay_attempt(cmd, pc);
}

static struct command_result *handle_pay(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *params)
{
	u64 *msatoshi;
	struct bolt11 *b11;
	const char *b11str;
	char *fail;
	double *riskfactor;
	unsigned int *retryfor;
	struct pay_command *pc = tal(cmd, struct pay_command);
	double *maxfeepercent;
	unsigned int *maxdelay;
	u64 *exemptfee;

	setup_locale();

	if (!param(cmd, buf, params,
		   p_req("bolt11", param_string, &b11str),
		   p_opt("msatoshi", param_u64, &msatoshi),
		   p_opt("description", param_string, &pc->desc),
		   p_opt_def("riskfactor", param_double, &riskfactor, 1.0),
		   p_opt_def("maxfeepercent", param_percent, &maxfeepercent, 0.5),
		   p_opt_def("retry_for", param_number, &retryfor, 60),
		   p_opt_def("maxdelay", param_number, &maxdelay,
			     /* FIXME! */
			     14 * 24 * 6),
		   p_opt_def("exemptfee", param_u64, &exemptfee, 5000),
		   NULL))
		return NULL;

	b11 = bolt11_decode(cmd, b11str, pc->desc, &fail);
	if (!b11) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid bolt11: %s", fail);
	}

	if (time_now().ts.tv_sec > b11->timestamp + b11->expiry) {
		return command_fail(cmd, PAY_INVOICE_EXPIRED, "Invoice expired");
	}

	if (b11->msatoshi) {
		if (msatoshi) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter unnecessary");
		}
		pc->msatoshi = *b11->msatoshi;
	} else {
		if (!msatoshi) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter required");
		}
		pc->msatoshi = *msatoshi;
	}

	pc->maxfeepercent = *maxfeepercent;
	pc->maxdelay = *maxdelay;
	pc->exemptfee = *exemptfee;
	pc->riskfactor = *riskfactor;
	pc->dest = type_to_string(cmd, struct pubkey, &b11->receiver_id);
	pc->payment_hash = type_to_string(pc, struct sha256,
					  &b11->payment_hash);
	pc->stoptime = timeabs_add(time_now(), time_from_sec(*retryfor));
	pc->attempts = tal_arr(cmd, struct pay_attempt, 0);
	pc->excludes = tal_arr(cmd, const char *, 0);

	/* Get capacities of local channels. */
	return send_outreq(cmd, "listpeers", listpeers_done, forward_error, pc,
			   " ");
}

static const struct plugin_command commands[] = { {
		"pay2",
		"Send payment specified by {bolt11} with {msatoshi}",
		"Try to send a payment, retrying {retry_for} seconds before giving up",
		handle_pay
	}
};

int main(int argc, char *argv[])
{
	plugin_main(argv, NULL, commands, ARRAY_SIZE(commands));
}
