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
	if (!t)
		plugin_err("getroute gave no 'route'? '%.*s'",
			   result->end - result->start, buf);

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

	/* FIXME! */
	double *maxfeepercent;
	unsigned int *maxdelay;
	unsigned int *exemptfee;

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
		   p_opt_def("exemptfee", param_number, &exemptfee, 5000),
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

	pc->riskfactor = *riskfactor;
	pc->dest = type_to_string(cmd, struct pubkey, &b11->receiver_id);
	pc->payment_hash = type_to_string(pc, struct sha256,
					  &b11->payment_hash);
	pc->stoptime = timeabs_add(time_now(), time_from_sec(*retryfor));
	pc->attempts = tal_arr(cmd, struct pay_attempt, 0);
	pc->excludes = tal_arr(cmd, const char *, 0);

	return start_pay_attempt(cmd, pc);
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
