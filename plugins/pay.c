#include <ccan/array_size/array_size.h>
#include <ccan/intmap/intmap.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/type_to_string.h>
#include <plugins/libplugin.h>

struct pay_command {
	/* Payment hash, as text. */
	const char *payment_hash;

	/* Description, if any. */
	const char *desc;
};

static struct command_result *sendpay_done(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *result,
					   struct pay_command *pc)
{
	return send_outreq(cmd, "waitsendpay",
			   forward_result, forward_error, pc,
			   "'payment_hash': '%s', 'timeout': 60",
			   pc->payment_hash);
}

static struct command_result *getroute_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct pay_command *pc)
{
	const jsmntok_t *t = json_get_member(buf, result, "route");
	char *json_desc;
	if (!t)
		plugin_err("getroute gave no 'route'? '%.*s'",
			   result->end - result->start, buf);

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

static struct command_result *handle_pay(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *params)
{
	u64 *msatoshi;
	struct bolt11 *b11;
	const char *b11str;
	char *fail;
	double *riskfactor;
	struct pay_command *pc = tal(cmd, struct pay_command);

	/* FIXME! */
	double *maxfeepercent;
	unsigned int *retryfor;
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

	if (b11->msatoshi) {
		if (msatoshi) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter unnecessary");
		}
	} else {
		if (!msatoshi) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter required");
		}
		b11->msatoshi = tal_steal(b11, msatoshi);
	}

	pc->payment_hash = type_to_string(pc, struct sha256,
					  &b11->payment_hash);

	/* OK, ask for route to destination */
	return send_outreq(cmd, "getroute", getroute_done, forward_error, pc,
			   "'id': '%s',"
			   "'msatoshi': %"PRIu64","
			   "'riskfactor': %f",
			   type_to_string(tmpctx, struct pubkey, &b11->receiver_id),
			   *b11->msatoshi, *riskfactor);
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
