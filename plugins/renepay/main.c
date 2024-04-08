#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/bolt12_merkle.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/utils.h>
#include <errno.h>
#include <plugins/renepay/json.h>
#include <plugins/renepay/mods.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/routetracker.h>
#include <stdio.h>

// TODO(eduardo): notice that pending attempts performed with another
// pay plugin are not considered by the uncertainty network in renepay,
// it would be nice if listsendpay would give us the route of pending
// sendpays.

struct pay_plugin *pay_plugin;

static void memleak_mark(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, pay_plugin);

	// TODO is this necessary?
	// memleak_scan_htable(memtable, &pay_plugin->chan_extra_map->raw);
	// memleak_scan_htable(memtable, &pay_plugin->payment_map->raw);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	size_t num_channel_updates_rejected;

	tal_steal(p, pay_plugin);
	pay_plugin->plugin = p;
	pay_plugin->last_time = 0;

	rpc_scan(p, "getinfo", take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &pay_plugin->my_id));

	rpc_scan(p, "listconfigs",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{configs:"
		 "{max-locktime-blocks:{value_int:%},"
		 "experimental-offers:{set:%}}}",
		 JSON_SCAN(json_to_number, &pay_plugin->maxdelay_default),
		 JSON_SCAN(json_to_bool, &pay_plugin->exp_offers)
		 );

	list_head_init(&pay_plugin->payments);

	pay_plugin->payment_map = tal(pay_plugin, struct payment_map);
	payment_map_init(pay_plugin->payment_map);

	pay_plugin->route_map = tal(pay_plugin,struct route_map);
	route_map_init(pay_plugin->route_map);

	pay_plugin->gossmap = gossmap_load(pay_plugin,
					   GOSSIP_STORE_FILENAME,
					   &num_channel_updates_rejected);

	if (!pay_plugin->gossmap)
		plugin_err(p, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));
	if (num_channel_updates_rejected)
		plugin_log(p, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_channel_updates_rejected);
	pay_plugin->uncertainty = uncertainty_new(pay_plugin);
	uncertainty_update(pay_plugin->uncertainty, pay_plugin->gossmap);

	plugin_set_memleak_handler(p, memleak_mark);
	return NULL;
}

static struct command_result *json_paystatus(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{
	const char *invstring;
	struct json_stream *ret;
	struct payment *p;

	if (!param(cmd, buf, params,
		   p_opt("invstring", param_invstring, &invstring),
		   NULL))
		return command_param_failed();

	ret = jsonrpc_stream_success(cmd);
	json_array_start(ret, "paystatus");
	if(invstring)
	{
		/* select the payment that matches this invoice */

		if (bolt12_has_prefix(invstring))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "BOLT12 invoices are not yet supported.");

		char *fail;
		struct bolt11 *b11 =
		    bolt11_decode(tmpctx, invstring, plugin_feature_set(cmd->plugin),
				  NULL, chainparams, &fail);
		if (b11 == NULL)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt11: %s", fail);

		struct payment *payment =
		    payment_map_get(pay_plugin->payment_map, b11->payment_hash);

		if(payment)
		{
			json_object_start(ret, NULL);
			json_add_payment(ret, payment);
			json_object_end(ret);
		}
	}else
	{
		/* show all payments */
		// TODO: loop over the payment_map, remove pay_plugin->payments
		// list
		// seeconst char *fmt_chan_extra_map(const tal_t *ctx, struct chan_extra_map *chan_extra_map)
		list_for_each(&pay_plugin->payments, p, list) {
			json_object_start(ret, NULL);
			json_add_payment(ret, p);
			json_object_end(ret);
		}
	}
	json_array_end(ret);

	return command_finished(cmd, ret);
}

static struct command_result * payment_start(struct payment *p)
{
	assert(p);
	p->status = PAYMENT_PENDING;
	plugin_log(pay_plugin->plugin, LOG_DBG, "Starting renepay");
	p->exec_state = 0;
	return payment_continue(p);
}

static struct command_result *json_pay(struct command *cmd, const char *buf,
				       const jsmntok_t *params)
{
	/* === Parse command line arguments === */
	// TODO check if we leak some of these temporary variables

	const char *invstr;
	struct amount_msat *msat;
	struct amount_msat *maxfee;
	u32 *maxdelay;
	u32 *retryfor;
	const char *description;
	const char *label;

	// dev options
	bool *use_shadow;

	// MCF options
	u64 *base_fee_penalty_millionths; // base fee to proportional fee
	u64 *prob_cost_factor_millionths; // prob. cost to proportional fee
	u64 *riskfactor_millionths; // delay to proportional proportional fee
	u64 *min_prob_success_millionths; // target probability

	if (!param(cmd, buf, params,
		   p_req("invstring", param_invstring, &invstr),
		   p_opt("amount_msat", param_msat, &msat),
		   p_opt("maxfee", param_msat, &maxfee),

		   p_opt_def("maxdelay", param_number, &maxdelay,
			     /* maxdelay has a configuration default value named
			      * "max-locktime-blocks", this is retrieved at
			      * init. */
			     pay_plugin->maxdelay_default),

		   p_opt_def("retry_for", param_number, &retryfor,
			     60), // 60 seconds
		   p_opt("description", param_string, &description),
		   p_opt("label", param_string, &label),

		   // FIXME add support for offers
		   // p_opt("localofferid", param_sha256, &local_offer_id),

		   p_opt_dev("dev_use_shadow", param_bool, &use_shadow, true),

		   // MCF options
		   p_opt_dev("dev_base_fee_penalty", param_millionths,
			     &base_fee_penalty_millionths,
			     10000000), // default is 10.0
		   p_opt_dev("dev_prob_cost_factor", param_millionths,
			     &prob_cost_factor_millionths,
			     10000000), // default is 10.0
		   p_opt_dev("dev_riskfactor", param_millionths,
			     &riskfactor_millionths, 1), // default is 1e-6
		   p_opt_dev("dev_min_prob_success", param_millionths,
			     &min_prob_success_millionths,
			     900000), // default is 0.9
		   NULL))
		return command_param_failed();

	/* === Parse invoice === */

	// FIXME: add support for bolt12 invoices
	if (bolt12_has_prefix(invstr))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "BOLT12 invoices are not yet supported.");

	char *fail;
	struct bolt11 *b11 =
	    bolt11_decode(tmpctx, invstr, plugin_feature_set(cmd->plugin),
			  description, chainparams, &fail);
	if (b11 == NULL)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid bolt11: %s", fail);

	/* Sanity check */
	if (feature_offered(b11->features, OPT_VAR_ONION) &&
	    !b11->payment_secret)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid bolt11:"
				    " sets feature var_onion with no secret");
	/* BOLT #11:
	 * A reader:
	 *...
	 * - MUST check that the SHA2 256-bit hash in the `h` field
	 *   exactly matches the hashed description.
	 */
	if (!b11->description) {
		if (!b11->description_hash)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "Invalid bolt11: missing description");

		if (!description)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "bolt11 uses description_hash, but you did "
			    "not provide description parameter");
	}

	if (b11->msat) {
		// amount is written in the invoice
		if (msat)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "amount_msat parameter unnecessary");
		msat = b11->msat;
	} else {
		// amount is not written in the invoice
		if (!msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "amount_msat parameter required");
	}

	// Default max fee is 5 sats, or 0.5%, whichever is *higher*
	if (!maxfee) {
		struct amount_msat fee = amount_msat_div(*msat, 200);
		if (amount_msat_less(fee, AMOUNT_MSAT(5000)))
			fee = AMOUNT_MSAT(5000);
		maxfee = tal_dup(tmpctx, struct amount_msat, &fee);
	}

	const u64 now_sec = time_now().ts.tv_sec;
	if (now_sec > (b11->timestamp + b11->expiry))
		return command_fail(cmd, PAY_INVOICE_EXPIRED,
				    "Invoice expired");

	/* === Get payment === */

	// one payment_hash one payment is not assumed, it is enforced
	struct payment *payment =
	    payment_map_get(pay_plugin->payment_map, b11->payment_hash);

	if(!payment)
	{
		payment = payment_new(
			tmpctx,
			&b11->payment_hash,
			take(invstr),
			take(label),
			take(description),
			b11->payment_secret,
			b11->metadata,
			cast_const2(const struct route_info**, b11->routes),
			&b11->receiver_id,
			*msat,
			*maxfee,
			*maxdelay,
			*retryfor,
			b11->min_final_cltv_expiry,
			*base_fee_penalty_millionths,
			*prob_cost_factor_millionths,
			*riskfactor_millionths,
			*min_prob_success_millionths,
			use_shadow);

		if (!payment)
			return command_fail(cmd, PLUGIN_ERROR,
					    "failed to create a new payment");
		if (!payment_register_command(payment, cmd))
			return command_fail(cmd, PLUGIN_ERROR,
					    "failed to register command");

		// good to go
		payment = tal_steal(pay_plugin, payment);

		// FIXME do we really need a list here?
		list_add_tail(&pay_plugin->payments, &payment->list);
		payment_map_add(pay_plugin->payment_map, payment);

		return payment_start(payment);
	}

	/* === Start or continue payment === */
	if (payment->status == PAYMENT_SUCCESS) {
		assert(payment_commands_empty(payment));
		// this payment is already a success, we show the result
		struct json_stream *result = jsonrpc_stream_success(cmd);
		json_add_payment(result, payment);
		return command_finished(cmd, result);
	}

	if (payment->status == PAYMENT_FAIL) {
		// FIXME: should we refuse to pay if the invoices are different?
		// or should we consider this a new payment?
		if (!payment_update(payment,
				    *maxfee,
				    *maxdelay,
				    *retryfor,
				    b11->min_final_cltv_expiry,
				    *base_fee_penalty_millionths,
				    *prob_cost_factor_millionths,
				    *riskfactor_millionths,
				    *min_prob_success_millionths,
				    use_shadow))
			return command_fail(
			    cmd, PLUGIN_ERROR,
			    "failed to update the payment parameters");

		// this payment already failed, we try again
		assert(payment_commands_empty(payment));
		if (!payment_register_command(payment, cmd))
			return command_fail(cmd, PLUGIN_ERROR,
					    "failed to register command");

		return payment_start(payment);
	}

	// else: this payment is pending we continue its execution, we merge all
	// calling cmds into a single payment request
	assert(payment->status == PAYMENT_PENDING);
	if (!payment_register_command(payment, cmd))
		return command_fail(cmd, PLUGIN_ERROR,
				    "failed to register command");
	return command_still_pending(cmd);
}

static const struct plugin_command commands[] = {
	{
		"renepaystatus",
		"payment",
		"Detail status of attempts to pay {bolt11}, or all",
		"Covers both old payments and current ones.",
		json_paystatus
	},
	{
		"renepay",
		"payment",
		"Send payment specified by {invstring}",
		"Attempt to pay an invoice.",
		json_pay
	},
};

static const struct plugin_notification notifications[] = {
	{
		"sendpay_success",
		notification_sendpay_success,
	},
	{
		"sendpay_failure",
		notification_sendpay_failure,
	}
};

int main(int argc, char *argv[])
{
	setup_locale();

	/* Most gets initialized in init(), but set debug options here. */
	pay_plugin = tal(NULL, struct pay_plugin);
	pay_plugin->debug_mcf = pay_plugin->debug_payflow = false;

	plugin_main(
		argv,
		init,
		PLUGIN_RESTARTABLE,
		/* init_rpc */ true,
		/* features */ NULL,
		commands, ARRAY_SIZE(commands),
		notifications, ARRAY_SIZE(notifications),
		/* hooks */ NULL, 0,
		/* notification topics */ NULL, 0,
		plugin_option("renepay-debug-mcf", "flag",
			"Enable renepay MCF debug info.",
			flag_option, &pay_plugin->debug_mcf),
		plugin_option("renepay-debug-payflow", "flag",
			"Enable renepay payment flows debug info.",
			flag_option, &pay_plugin->debug_payflow),
		NULL);

	return 0;
}
