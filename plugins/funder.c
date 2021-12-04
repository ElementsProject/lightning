/* This is a plugin which allows you to specify
 * your policy for accepting/dual-funding incoming
 * v2 channel-open requests.
 *
 *  "They say marriages are made in Heaven.
 *   But so is funder and lightning."
 *     - Clint Eastwood
 *  (because funder rhymes with thunder)
 *
 */
#include "config.h"
#include <bitcoin/feerate.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/json_stream.h>
#include <common/json_tok.h>
#include <common/memleak.h>
#include <common/overflows.h>
#include <common/psbt_open.h>
#include <common/type_to_string.h>
#include <plugins/funder_policy.h>
#include <plugins/libplugin.h>

/* In-progress channel opens */
static struct list_head pending_opens;

/* Current set policy */
static struct funder_policy *current_policy;

struct pending_open {
	struct list_node list;
	struct plugin *p;

	struct node_id peer_id;
	struct channel_id channel_id;

	const struct wally_psbt *psbt;
};

static struct pending_open *
find_channel_pending_open(const struct channel_id *cid)
{
	struct pending_open *open;
	list_for_each(&pending_opens, open, list) {
		if (channel_id_eq(&open->channel_id, cid))
			return open;
	}
	return NULL;
}

static struct pending_open *
new_channel_open(const tal_t *ctx,
		 struct plugin *p,
		 const struct node_id id,
		 const struct channel_id cid,
		 const struct wally_psbt *psbt STEALS)
{
	struct pending_open *open;

	/* Make sure we haven't gotten this yet */
	assert(!find_channel_pending_open(&cid));

	open = tal(ctx, struct pending_open);
	open->p = p;
	open->peer_id = id;
	open->channel_id = cid;
	open->psbt = tal_steal(open, psbt);

	list_add_tail(&pending_opens, &open->list);

	return open;
}

static struct command_result *
unreserve_done(struct command *cmd UNUSED,
	       const char *buf,
	       const jsmntok_t *result,
	       struct pending_open *open)
{
	plugin_log(open->p, LOG_DBG,
		   "`unreserveinputs` for channel %s completed. %*.s",
		   type_to_string(tmpctx, struct channel_id, &open->channel_id),
		   json_tok_full_len(result),
		   json_tok_full(buf, result));

	return command_done();
}

static void unreserve_psbt(struct pending_open *open)
{
	struct out_req *req;

	plugin_log(open->p, LOG_DBG,
		   "Calling `unreserveinputs` for channel %s",
		   type_to_string(tmpctx, struct channel_id,
				  &open->channel_id));

	req = jsonrpc_request_start(open->p, NULL,
				    "unreserveinputs",
				    unreserve_done, unreserve_done,
				    open);
	json_add_psbt(req->js, "psbt", open->psbt);
	send_outreq(open->p, req);
}

static void cleanup_peer_pending_opens(const struct node_id *id)
{
	struct pending_open *i, *next;
	list_for_each_safe(&pending_opens, i, next, list) {
		if (node_id_eq(&i->peer_id, id)) {
			unreserve_psbt(i);
			list_del(&i->list);
		}
	}
}

static struct pending_open *
cleanup_channel_pending_open(const struct channel_id *cid)
{
	struct pending_open *open;
	open = find_channel_pending_open(cid);

	if (!open)
		return NULL;

	list_del(&open->list);
	return open;
}

static struct command_result *
command_hook_cont_psbt(struct command *cmd, struct wally_psbt *psbt)
{
	struct json_stream *response;

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "result", "continue");
	json_add_psbt(response, "psbt", psbt);
	return command_finished(cmd, response);
}

static struct command_result *
signpsbt_done(struct command *cmd,
	      const char *buf,
	      const jsmntok_t *result,
	      struct pending_open *open)
{
	struct wally_psbt *signed_psbt;
	const char *err;

	plugin_log(cmd->plugin, LOG_DBG,
		   "`signpsbt` done for channel %s",
		   type_to_string(tmpctx, struct channel_id,
				  &open->channel_id));
	err = json_scan(tmpctx, buf, result,
			"{signed_psbt:%}",
			JSON_SCAN_TAL(cmd, json_to_psbt, &signed_psbt));

	if (err)
		plugin_err(cmd->plugin,
			   "`signpsbt` payload did not scan %s: %*.s",
			   err, json_tok_full_len(result),
			   json_tok_full(buf, result));

	cleanup_channel_pending_open(&open->channel_id);
	return command_hook_cont_psbt(cmd, signed_psbt);
}

static struct command_result *
json_openchannel2_sign_call(struct command *cmd,
			    const char *buf,
			    const jsmntok_t *params)
{
	struct channel_id cid;
	struct wally_psbt *psbt;
	const char *err;
	struct out_req *req;
	struct pending_open *open;
	size_t count;

	err = json_scan(tmpctx, buf, params,
			"{openchannel2_sign:"
			"{channel_id:%,psbt:%}}",
			JSON_SCAN(json_to_channel_id, &cid),
			JSON_SCAN_TAL(cmd, json_to_psbt, &psbt));

	if (err)
		plugin_err(cmd->plugin,
			   "`openchannel2_sign` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* If we're not tracking this open, just pass through */
	open = find_channel_pending_open(&cid);
	if (!open) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "nothing to sign for channel %s",
			   type_to_string(tmpctx, struct channel_id, &cid));
		return command_hook_cont_psbt(cmd, psbt);
	}

	if (!psbt_has_our_input(psbt)) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "no inputs to sign for channel %s",
			   type_to_string(tmpctx, struct channel_id, &cid));
		return command_hook_cont_psbt(cmd, psbt);
	}

	plugin_log(cmd->plugin, LOG_DBG,
		   "openchannel_sign PSBT is %s",
		   type_to_string(tmpctx, struct wally_psbt, psbt));

	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "signpsbt",
				    &signpsbt_done,
				    &forward_error,
				    open);
	json_add_psbt(req->js, "psbt", psbt);
	/* Use input markers to identify which inputs
	 * are ours, only sign those */
	json_array_start(req->js, "signonly");
	count = 0;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (psbt_input_is_ours(&psbt->inputs[i])) {
			json_add_num(req->js, NULL, i);
			count++;
		}
	}
	json_array_end(req->js);

	plugin_log(cmd->plugin, LOG_DBG,
		   "calling `signpsbt` for channel %s for %zu input%s",
		   type_to_string(tmpctx, struct channel_id,
				  &open->channel_id), count,
		   count == 1 ? "" : "s");
	return send_outreq(cmd->plugin, req);
}

static struct command_result *
json_openchannel2_changed_call(struct command *cmd,
			       const char *buf,
			       const jsmntok_t *params)
{
	struct channel_id cid;
	struct wally_psbt *psbt;
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{openchannel2_changed:"
			"{channel_id:%,psbt:%}}",
			JSON_SCAN(json_to_channel_id, &cid),
			JSON_SCAN_TAL(cmd, json_to_psbt, &psbt));

	if (err)
		plugin_err(cmd->plugin,
			   "`openchannel2_changed` payload did not"
			   " scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	plugin_log(cmd->plugin, LOG_DBG,
		   "openchannel_changed PSBT is %s",
		   type_to_string(tmpctx, struct wally_psbt, psbt));

	/* FIXME: do we have any additions or updates to make based
	 * on their changes? */
	/* For now, we assume we're the same as before and continue
	 * on as planned */
	return command_hook_cont_psbt(cmd, psbt);
}

/* Tiny struct to pass info to callback for fundpsbt */
struct open_info {
	struct channel_id cid;
	struct node_id id;
	struct amount_sat our_funding;
	struct amount_sat their_funding;
	struct amount_sat channel_max;
	u64 funding_feerate_perkw;
	u32 locktime;
	u32 lease_blockheight;
	u32 node_blockheight;
	struct amount_sat requested_lease;
};

static struct open_info *new_open_info(const tal_t *ctx)
{
	struct open_info *info = tal(ctx, struct open_info);

	info->requested_lease = AMOUNT_SAT(0);
	info->lease_blockheight = 0;
	info->node_blockheight = 0;

	return info;
}

static struct command_result *
psbt_funded(struct command *cmd,
	    const char *buf,
	    const jsmntok_t *result,
	    struct open_info *info)
{
	struct wally_psbt *psbt;
	struct json_stream *response;
	struct amount_msat our_funding_msat;

	const char *err;

	err = json_scan(tmpctx, buf, result,
			"{psbt:%}",
			JSON_SCAN_TAL(tmpctx, json_to_psbt, &psbt));
	if (err)
		plugin_err(cmd->plugin,
			   "`fundpsbt` response did not scan %s: %.*s",
			   err, json_tok_full_len(result),
			   json_tok_full(buf, result));

	/* We also mark all of our inputs as *ours*, so we
	 * can easily identify them for `signpsbt` later */
	for (size_t i = 0; i < psbt->num_inputs; i++)
		psbt_input_mark_ours(psbt, &psbt->inputs[i]);

	new_channel_open(cmd->plugin, cmd->plugin,
			 info->id, info->cid, psbt);

	if (!amount_sat_to_msat(&our_funding_msat, info->our_funding))
		abort();

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "result", "continue");
	json_add_psbt(response, "psbt", psbt);
	json_add_amount_msat_only(response, "our_funding_msat",
				  our_funding_msat);

	/* If we're accepting an lease request, *and* they've
	 * requested one, fill in our most recent infos */
	if (current_policy->rates && !amount_sat_zero(info->requested_lease))
		json_add_lease_rates(response, current_policy->rates);

	return command_finished(cmd, response);
}

static struct command_result *
psbt_fund_failed(struct command *cmd,
		 const char *buf,
		 const jsmntok_t *error,
		 struct open_info *info)
{
	/* Attempt to fund a psbt for this open failed.
	 * We probably ran out of funds (race?) */
	plugin_log(cmd->plugin, LOG_INFORM,
		   "Unable to secure %s from wallet,"
		   " continuing channel open to %s"
		   " without our participation. err %.*s",
		   type_to_string(tmpctx, struct amount_sat,
				  &info->our_funding),
		   type_to_string(tmpctx, struct node_id,
				  &info->id),
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	return command_hook_success(cmd);
}

static struct command_result *
listfunds_success(struct command *cmd,
		  const char *buf,
		  const jsmntok_t *result,
		  struct open_info *info)
{
	struct amount_sat available_funds, est_fee;
	const jsmntok_t *outputs_tok, *tok;
	struct out_req *req;
	size_t i;
	const char *funding_err;

	outputs_tok = json_get_member(buf, result, "outputs");
	if (!outputs_tok)
		plugin_err(cmd->plugin,
			   "`listfunds` payload has no outputs token: %*.s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	available_funds = AMOUNT_SAT(0);
	json_for_each_arr(i, tok, outputs_tok) {
		struct amount_sat val;
		bool is_reserved, is_p2sh;
		char *status;
		const char *err;

		err = json_scan(tmpctx, buf, tok,
				"{amount_msat:%"
				",status:%"
				",reserved:%}",
				JSON_SCAN(json_to_sat, &val),
				JSON_SCAN_TAL(cmd, json_strdup, &status),
				JSON_SCAN(json_to_bool, &is_reserved));
		if (err)
			plugin_err(cmd->plugin,
				   "`listfunds` payload did not scan. %s: %*.s",
				   err, json_tok_full_len(result),
				   json_tok_full(buf, result));

		/* is it a p2sh output? */
		if (json_get_member(buf, tok, "redeemscript"))
			is_p2sh = true;
		else
			is_p2sh = false;

		/* The estimated fee per utxo. */
		est_fee = amount_tx_fee(info->funding_feerate_perkw,
					bitcoin_tx_input_weight(is_p2sh, 110));

		/* we skip reserved funds */
		if (is_reserved)
			continue;

		/* we skip unconfirmed+spent funds */
		if (!streq(status, "confirmed"))
			continue;

		/* Don't include outputs that can't cover their weight;
		 *  subtract the fee for this utxo out of the utxo */
		if (!amount_sat_sub(&val, val, est_fee))
			continue;

		if (!amount_sat_add(&available_funds, available_funds, val))
			plugin_err(cmd->plugin,
				   "`listfunds` overflowed output values");
	}

	funding_err = calculate_our_funding(current_policy,
					    info->id,
					    info->their_funding,
					    available_funds,
					    info->channel_max,
					    info->requested_lease,
					    &info->our_funding);
	plugin_log(cmd->plugin, LOG_DBG,
		   "Policy %s returned funding amount of %s. %s",
		   funder_policy_desc(tmpctx, current_policy),
		   type_to_string(tmpctx, struct amount_sat,
				  &info->our_funding),
		   funding_err ? funding_err : "");

	if (amount_sat_zero(info->our_funding))
		return command_hook_success(cmd);

	plugin_log(cmd->plugin, LOG_DBG,
		   "Funding channel %s with %s (their input %s)",
		   type_to_string(tmpctx, struct channel_id, &info->cid),
		   type_to_string(tmpctx, struct amount_sat,
				  &info->our_funding),
		   type_to_string(tmpctx, struct amount_sat,
				  &info->their_funding));

	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "fundpsbt",
				    &psbt_funded,
				    &psbt_fund_failed,
				    info);
	json_add_bool(req->js, "reserve", true);
	json_add_string(req->js, "satoshi",
			type_to_string(tmpctx, struct amount_sat,
				       &info->our_funding));
	json_add_string(req->js, "feerate",
			tal_fmt(tmpctx, "%"PRIu64"%s",
				info->funding_feerate_perkw,
				feerate_style_name(FEERATE_PER_KSIPA)));
	/* Our startweight is zero because we're freeriding on their open
	 * transaction ! */
	json_add_num(req->js, "startweight", 0);
	json_add_num(req->js, "min_witness_weight", 110);
	json_add_bool(req->js, "excess_as_change", true);
	json_add_num(req->js, "locktime", info->locktime);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *
listfunds_failed(struct command *cmd,
		 const char *buf,
		 const jsmntok_t *error,
		 struct open_info *info)
{

	/* Something went wrong fetching the funds info
	 * for our wallet. Just keep going */
	plugin_log(cmd->plugin, LOG_INFORM,
		   "Unable to fetch wallet funds info."
		   " Continuing channel open to %s"
		   " without our participation. err %.*s",
		   type_to_string(tmpctx, struct node_id,
				  &info->id),
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	return command_hook_success(cmd);
}

static struct command_result *
json_openchannel2_call(struct command *cmd,
		       const char *buf,
		       const jsmntok_t *params)
{
	struct open_info *info = tal(cmd, struct open_info);
	struct amount_msat max_htlc_inflight, htlc_minimum;
	u64 commitment_feerate_perkw,
	    feerate_our_max, feerate_our_min;
	u32 to_self_delay, max_accepted_htlcs;
	u16 channel_flags;
	const char *err;
	struct out_req *req;

	err = json_scan(tmpctx, buf, params,
			"{openchannel2:"
			"{id:%"
			",channel_id:%"
			",their_funding:%"
			",max_htlc_value_in_flight_msat:%"
			",htlc_minimum_msat:%"
			",funding_feerate_per_kw:%"
			",commitment_feerate_per_kw:%"
			",feerate_our_max:%"
			",feerate_our_min:%"
			",to_self_delay:%"
			",max_accepted_htlcs:%"
			",channel_flags:%"
			",locktime:%}}",
			JSON_SCAN(json_to_node_id, &info->id),
			JSON_SCAN(json_to_channel_id, &info->cid),
			JSON_SCAN(json_to_sat, &info->their_funding),
			JSON_SCAN(json_to_msat, &max_htlc_inflight),
			JSON_SCAN(json_to_msat, &htlc_minimum),
			JSON_SCAN(json_to_u64, &info->funding_feerate_perkw),
			JSON_SCAN(json_to_u64, &commitment_feerate_perkw),
			JSON_SCAN(json_to_u64, &feerate_our_max),
			JSON_SCAN(json_to_u64, &feerate_our_min),
			JSON_SCAN(json_to_u32, &to_self_delay),
			JSON_SCAN(json_to_u32, &max_accepted_htlcs),
			JSON_SCAN(json_to_u16, &channel_flags),
			JSON_SCAN(json_to_u32, &info->locktime));

	if (err)
		plugin_err(cmd->plugin,
			   "`openchannel2` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	err = json_scan(tmpctx, buf, params,
			"{openchannel2:{"
			"requested_lease_msat:%"
			",lease_blockheight_start:%"
			",node_blockheight:%}}",
			JSON_SCAN(json_to_sat, &info->requested_lease),
			JSON_SCAN(json_to_u32, &info->node_blockheight),
			JSON_SCAN(json_to_u32, &info->lease_blockheight));

	/* These aren't necessarily included */
	if (err) {
		info->requested_lease = AMOUNT_SAT(0);
		info->node_blockheight = 0;
		info->lease_blockheight = 0;
	}

	/* If there's no channel_max, it's actually infinity */
	err = json_scan(tmpctx, buf, params,
			"{openchannel2:{channel_max_msat:%}}",
			JSON_SCAN(json_to_sat, &info->channel_max));
	if (err)
		info->channel_max = AMOUNT_SAT(UINT64_MAX);

	/* We don't fund anything that's above or below our feerate */
	if (info->funding_feerate_perkw < feerate_our_min
	    || info->funding_feerate_perkw > feerate_our_max) {

		plugin_log(cmd->plugin, LOG_DBG,
			   "their feerate %"PRIu64" is out of"
			   " our bounds (%"PRIu64"-%"PRIu64")",
			   info->funding_feerate_perkw,
			   feerate_our_min,
			   feerate_our_max);

		return command_hook_success(cmd);
	}

	/* If they've requested funds, but we're not actually
	 * supporting requested funds...*/
	if (!current_policy->rates &&
	    !amount_sat_zero(info->requested_lease)) {
		struct json_stream *res = jsonrpc_stream_success(cmd);
		json_add_string(res, "result", "reject");
		json_add_string(res, "error_message",
				"Peer requested funds but we're not advertising"
				" liquidity right now");
		return command_finished(cmd, res);
	}


	/* Check that their block height isn't too far behind */
	if (!amount_sat_zero(info->requested_lease)) {
		u32 upper_bound, lower_bound;

		/* BOLT- #2:
		 * The receiving node:
		 * - MAY fail the negotiation if:  ...
		 *   - if the `option_will_fund` tlv is present and:
		 *    - the `blockheight` is considered too far in the
		 *      past or future
		 */
		/* We consider 24 hrs too far out */
		upper_bound = info->node_blockheight + 24 * 6;
		lower_bound = info->node_blockheight - 24 * 6;

		/* Check overflow */
		if (upper_bound < info->node_blockheight)
			upper_bound = -1;
		if (lower_bound > info->node_blockheight)
			lower_bound = 0;

		if (upper_bound < info->lease_blockheight
		    || lower_bound > info->lease_blockheight) {

			plugin_log(cmd->plugin, LOG_DBG,
				   "their blockheight %d is out of"
				   " our bounds (ours is %d)",
				   info->lease_blockheight,
				   info->node_blockheight);

			return command_hook_success(cmd);
		}
	}

	/* Figure out what our funds are */
	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "listfunds",
				    &listfunds_success,
				    &listfunds_failed,
				    info);

	return send_outreq(cmd->plugin, req);
}

/* Peer has asked us to RBF */
static struct command_result *
json_rbf_channel_call(struct command *cmd,
		      const char *buf,
		      const jsmntok_t *params)
{
	struct open_info *info = new_open_info(cmd);
	u64 feerate_our_max, feerate_our_min;
	const char *err;
	struct out_req *req;

	err = json_scan(tmpctx, buf, params,
			"{rbf_channel:"
			"{id:%"
			",channel_id:%"
			",their_funding:%"
			",funding_feerate_per_kw:%"
			",feerate_our_max:%"
			",feerate_our_min:%"
			",locktime:%}}",
			JSON_SCAN(json_to_node_id, &info->id),
			JSON_SCAN(json_to_channel_id, &info->cid),
			JSON_SCAN(json_to_sat, &info->their_funding),
			JSON_SCAN(json_to_u64, &info->funding_feerate_perkw),
			JSON_SCAN(json_to_u64, &feerate_our_max),
			JSON_SCAN(json_to_u64, &feerate_our_min),
			JSON_SCAN(json_to_u32, &info->locktime));

	if (err)
		plugin_err(cmd->plugin,
			   "`rbf_channel` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* If there's no channel_max, it's actually infinity */
	err = json_scan(tmpctx, buf, params,
			"{rbf_channel:{channel_max_msat:%}}",
			JSON_SCAN(json_to_sat, &info->channel_max));
	if (err)
		info->channel_max = AMOUNT_SAT(UINT64_MAX);

	/* We don't fund anything that's above or below our feerate */
	if (info->funding_feerate_perkw < feerate_our_min
	    || info->funding_feerate_perkw > feerate_our_max) {

		plugin_log(cmd->plugin, LOG_DBG,
			   "their feerate %"PRIu64" is out of"
			   " our bounds (%"PRIu64"-%"PRIu64")",
			   info->funding_feerate_perkw,
			   feerate_our_min,
			   feerate_our_max);

		return command_hook_success(cmd);
	}

	/* Figure out what our funds are... same flow
	 * as with openchannel2 callback. We assume that THEY
	 * will use the same inputs, so we use whatever we want here */
	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "listfunds",
				    &listfunds_success,
				    &listfunds_failed,
				    info);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_disconnect(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *params)
{
	struct node_id id;
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{id:%}",
			JSON_SCAN(json_to_node_id, &id));
	if (err)
		plugin_err(cmd->plugin,
			   "`disconnect` notification payload did not"
			   " scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	plugin_log(cmd->plugin, LOG_DBG,
		   "Cleaning up inflights for peer id %s",
		   type_to_string(tmpctx, struct node_id, &id));

	cleanup_peer_pending_opens(&id);

	return notification_handled(cmd);
}

static struct command_result *json_channel_open_failed(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
	struct channel_id cid;
	struct pending_open *open;
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{channel_open_failed:"
			"{channel_id:%}}",
			JSON_SCAN(json_to_channel_id, &cid));
	if (err)
		plugin_err(cmd->plugin,
			   "`channel_open_failed` notification payload did"
			   " not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	plugin_log(cmd->plugin, LOG_DBG,
		   "Cleaning up inflight for channel_id %s",
		   type_to_string(tmpctx, struct channel_id, &cid));

	open = cleanup_channel_pending_open(&cid);
	if (open)
		unreserve_psbt(open);

	return notification_handled(cmd);
}

static void json_add_policy(struct json_stream *stream,
			    struct funder_policy *policy)
{
	json_add_string(stream, "summary",
			funder_policy_desc(stream, current_policy));
	json_add_string(stream, "policy",
			funder_opt_name(policy->opt));
	json_add_num(stream, "policy_mod", policy->mod);
	json_add_bool(stream, "leases_only", policy->leases_only);
	json_add_amount_sat_only(stream, "min_their_funding_msat",
				 policy->min_their_funding);
	json_add_amount_sat_only(stream, "max_their_funding_msat",
				 policy->max_their_funding);
	json_add_amount_sat_only(stream, "per_channel_min_msat",
				 policy->per_channel_min);
	json_add_amount_sat_only(stream, "per_channel_max_msat",
				 policy->per_channel_max);
	json_add_amount_sat_only(stream, "reserve_tank_msat",
				 policy->reserve_tank);
	json_add_num(stream, "fuzz_percent", policy->fuzz_factor);
	json_add_num(stream, "fund_probability", policy->fund_probability);

	if (policy->rates) {
		json_add_lease_rates(stream, policy->rates);
		json_add_string(stream, "compact_lease",
				lease_rates_tohex(tmpctx, policy->rates));
	}
}

static struct command_result *
param_funder_opt(struct command *cmd, const char *name,
		 const char *buffer, const jsmntok_t *tok,
		 enum funder_opt **opt)
{
	char *opt_str, *err;

	*opt = tal(cmd, enum funder_opt);
	opt_str = tal_strndup(cmd, buffer + tok->start,
			      tok->end - tok->start);

	err = funding_option(opt_str, *opt);
	if (err)
		return command_fail_badparam(cmd, name, buffer, tok, err);

	return NULL;
}


static struct command_result *
param_policy_mod(struct command *cmd, const char *name,
		 const char *buffer, const jsmntok_t *tok,
		 u64 **mod)
{
	struct amount_sat sats;
	char *arg_str, *err;

	*mod = tal(cmd, u64);
	arg_str = tal_strndup(cmd, buffer + tok->start,
			      tok->end - tok->start);

	err = u64_option(arg_str, *mod);
	if (err) {
		tal_free(err);
		if (!parse_amount_sat(&sats, arg_str, strlen(arg_str)))
			return command_fail_badparam(cmd, name,
						     buffer, tok, err);

		**mod = sats.satoshis; /* Raw: convert to u64 */
	}

	return NULL;
}

static struct command_result *
parse_lease_rates(struct command *cmd, const char *buffer,
		  const jsmntok_t *tok,
		  struct funder_policy *policy,
		  struct funder_policy *current_policy,
		  u32 *lease_fee_basis,
		  struct amount_sat *lease_fee_sats,
		  u32 *funding_weight,
		  u32 *channel_fee_max_proportional_thousandths,
		  struct amount_msat *chan_fee_msats)

{
	/* If there's already rates set, we start with those */
	if (!lease_rates_empty(current_policy->rates))
		policy->rates = tal_dup(policy, struct lease_rates,
					current_policy->rates);
	else if (lease_fee_basis
		 || lease_fee_sats
		 || funding_weight
		 || channel_fee_max_proportional_thousandths
		 || chan_fee_msats)
		policy->rates = default_lease_rates(policy);
	else
		policy->rates = NULL;

	/* Sometimes a local macro is neater than the alternative */
#define ASSIGN_OR_RETURN_FAIL(type, member)				\
	do {								\
		if (member &&						\
		    !assign_overflow_##type(&policy->rates->member, *member)) \
			return command_fail_badparam(cmd, #member,	\
						     buffer, tok, "overflow"); \
} while(0)

	ASSIGN_OR_RETURN_FAIL(u16, lease_fee_basis);
	ASSIGN_OR_RETURN_FAIL(u16, funding_weight);
	ASSIGN_OR_RETURN_FAIL(u16, channel_fee_max_proportional_thousandths);
#undef ASSIGN_OR_RETURN_FAIL

	if (chan_fee_msats
	    && !assign_overflow_u32(&policy->rates->channel_fee_max_base_msat,
				    chan_fee_msats->millisatoshis /* Raw: conversion */)) {
		return command_fail_badparam(cmd, "channel_fee_max_base_msat",
					     buffer, tok, "overflow");
	}
	if (lease_fee_sats
	    && !assign_overflow_u32(&policy->rates->lease_fee_base_sat,
				    lease_fee_sats->satoshis /* Raw: conversion */)) {
		return command_fail_badparam(cmd, "lease_fee_base_sat",
					     buffer, tok, "overflow");
	}

	return NULL;
}

static struct command_result *
leaserates_set(struct command *cmd, const char *buf,
	       const jsmntok_t *result,
	       struct funder_policy *policy)
{
	struct json_stream *res;

	/* Ok, we updated lightningd with latest info */
	res = jsonrpc_stream_success(cmd);
	json_add_policy(res, policy);
	return command_finished(cmd, res);
}

static struct command_result *
json_funderupdate(struct command *cmd,
		  const char *buf,
		  const jsmntok_t *params)
{
	struct amount_sat *min_their_funding, *max_their_funding,
			  *per_channel_min, *per_channel_max,
			  *reserve_tank, *lease_fee_sats;
	struct amount_msat *channel_fee_msats;
	u32 *fuzz_factor, *fund_probability, *chan_fee_ppt,
	    *lease_fee_basis, *funding_weight;
	u64 *mod;
	bool *leases_only;
	enum funder_opt *opt;
	const struct out_req *req;
	const char *err;
	struct command_result *res;
	struct funder_policy *policy = tal(cmd, struct funder_policy);

	if (!param(cmd, buf, params,
		   p_opt_def("policy", param_funder_opt, &opt,
			     current_policy->opt),
		   p_opt_def("policy_mod", param_policy_mod, &mod,
			     current_policy->mod),
		   p_opt_def("leases_only", param_bool, &leases_only,
			     current_policy->leases_only),
		   p_opt_def("min_their_funding_msat", param_sat,
			     &min_their_funding,
			     current_policy->min_their_funding),
		   p_opt_def("max_their_funding_msat", param_sat,
			     &max_their_funding,
			     current_policy->max_their_funding),
		   p_opt_def("per_channel_min_msat", param_sat,
			     &per_channel_min,
			     current_policy->per_channel_min),
		   p_opt_def("per_channel_max_msat", param_sat,
			     &per_channel_max,
			     current_policy->per_channel_max),
		   p_opt_def("reserve_tank_msat", param_sat, &reserve_tank,
			     current_policy->reserve_tank),
		   p_opt_def("fuzz_percent", param_number,
			     &fuzz_factor,
			     current_policy->fuzz_factor),
		   p_opt_def("fund_probability", param_number,
			     &fund_probability,
			     current_policy->fund_probability),
		   p_opt("lease_fee_base_msat", param_sat, &lease_fee_sats),
		   p_opt("lease_fee_basis", param_number, &lease_fee_basis),
		   p_opt("funding_weight", param_number, &funding_weight),
		   p_opt("channel_fee_max_base_msat", param_msat,
			 &channel_fee_msats),
		   p_opt("channel_fee_max_proportional_thousandths",
			 param_number, &chan_fee_ppt),
		   NULL))
		return command_param_failed();

	policy->opt = *opt;
	policy->mod = *mod;
	policy->min_their_funding = *min_their_funding;
	policy->max_their_funding = *max_their_funding;
	policy->per_channel_min = *per_channel_min;
	policy->per_channel_max = *per_channel_max;
	policy->reserve_tank = *reserve_tank;
	policy->fuzz_factor = *fuzz_factor;
	policy->fund_probability = *fund_probability;
	policy->leases_only = *leases_only;

	res = parse_lease_rates(cmd, buf, params,
				policy, current_policy,
				lease_fee_basis,
				lease_fee_sats,
				funding_weight,
				chan_fee_ppt,
				channel_fee_msats);
	if (res)
		return res;

	err = funder_check_policy(policy);
	if (err) {
		tal_free(policy);
		return command_done_err(cmd, JSONRPC2_INVALID_PARAMS,
					err, NULL);
	}

	tal_free(current_policy);
	current_policy = tal_steal(NULL, policy);

	/* Update lightningd, also */
	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "setleaserates",
				    &leaserates_set,
				    &forward_error,
				    current_policy);

	if (current_policy->rates)
		json_add_lease_rates(req->js, current_policy->rates);
	else {
		/* Add empty rates to turn off */
		struct lease_rates rates;
		memset(&rates, 0, sizeof(rates));
		json_add_lease_rates(req->js, &rates);
	}

	return send_outreq(cmd->plugin, req);
}

static const struct plugin_command commands[] = {
	{
		"funderupdate",
		"liquidity",
		"Configuration for dual-funding settings.",
		"Update current settings. Modifies how node reacts to"
		" incoming channel open requests. Responds with list"
		" of current configs.",
		json_funderupdate
	},
};

static void tell_lightningd_lease_rates(struct plugin *p,
					struct lease_rates *rates)
{
	struct json_out *jout;
	struct amount_sat val;
	struct amount_msat mval;

	/* Tell lightningd with our lease rates*/
	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');

	val = amount_sat(rates->lease_fee_base_sat);
	json_out_addstr(jout, "lease_fee_base_msat",
			type_to_string(tmpctx, struct amount_sat, &val));
	json_out_add(jout, "lease_fee_basis", false,
		     "%d", rates->lease_fee_basis);

	json_out_add(jout, "funding_weight", false,
		     "%d", rates->funding_weight);

	mval = amount_msat(rates->channel_fee_max_base_msat);
	json_out_addstr(jout, "channel_fee_max_base_msat",
			type_to_string(tmpctx, struct amount_msat, &mval));
	json_out_add(jout, "channel_fee_max_proportional_thousandths", false,
		     "%d", rates->channel_fee_max_proportional_thousandths);

	json_out_end(jout, '}');
	json_out_finished(jout);

	rpc_scan(p, "setleaserates", take(jout),
		 /* Unused */
		 "{lease_fee_base_msat:%}",
		 JSON_SCAN(json_to_sat, &val));

}

#if DEVELOPER
static void memleak_mark(struct plugin *p, struct htable *memtable)
{
	memleak_remove_region(memtable, &pending_opens, sizeof(pending_opens));
	memleak_remove_region(memtable, current_policy, sizeof(*current_policy));
}
#endif

static const char *init(struct plugin *p, const char *b, const jsmntok_t *t)
{
	const char *err;

	list_head_init(&pending_opens);

	err = funder_check_policy(current_policy);
	if (err)
		plugin_err(p, "Invalid parameter combination: %s", err);

	if (current_policy->rates)
		tell_lightningd_lease_rates(p, current_policy->rates);

#if DEVELOPER
	plugin_set_memleak_handler(p, memleak_mark);
#endif

	return NULL;
}

const struct plugin_hook hooks[] = {
	{
		"openchannel2",
		json_openchannel2_call,
	},
	{
		"openchannel2_changed",
		json_openchannel2_changed_call,
	},
	{
		"openchannel2_sign",
		json_openchannel2_sign_call,
	},
	{
		"rbf_channel",
		json_rbf_channel_call,
	},
};

const struct plugin_notification notifs[] = {
	{
		"channel_open_failed",
		json_channel_open_failed,
	},
	{
		"disconnect",
		json_disconnect,
	},
};

static char *option_channel_base(const char *arg, struct funder_policy *policy)
{
	struct amount_msat amt;

	if (!parse_amount_msat(&amt, arg, strlen(arg)))
		return tal_fmt(NULL, "Unable to parse amount '%s'", arg);

	if (!policy->rates)
		policy->rates = default_lease_rates(policy);

	if (!assign_overflow_u32(&policy->rates->channel_fee_max_base_msat,
				amt.millisatoshis)) /* Raw: conversion */
		return tal_fmt(NULL, "channel_fee_max_base_msat overflowed");

	return NULL;
}

static char *
option_channel_fee_proportional_thousandths_max(const char *arg,
						struct funder_policy *policy)
{
	if (!policy->rates)
		policy->rates = default_lease_rates(policy);
	return u16_option(arg, &policy->rates->channel_fee_max_proportional_thousandths);
}

static char *amount_option(const char *arg, struct amount_sat *amt)
{
	if (!parse_amount_sat(amt, arg, strlen(arg)))
		return tal_fmt(NULL, "Unable to parse amount '%s'", arg);

	return NULL;
}

static char *option_lease_fee_base(const char *arg,
				   struct funder_policy *policy)
{
	struct amount_sat amt;
	char *err;
	if (!policy->rates)
		policy->rates = default_lease_rates(policy);

	err = amount_option(arg, &amt);
	if (err)
		return err;

	if (!assign_overflow_u32(&policy->rates->lease_fee_base_sat,
				 amt.satoshis)) /* Raw: conversion */
		return tal_fmt(NULL, "lease_fee_base_sat overflowed");

	return NULL;
}

static char *option_lease_fee_basis(const char *arg,
				    struct funder_policy *policy)
{
	if (!policy->rates)
		policy->rates = default_lease_rates(policy);
	return u16_option(arg, &policy->rates->lease_fee_basis);
}

static char *option_lease_weight_max(const char *arg,
				     struct funder_policy *policy)
{
	if (!policy->rates)
		policy->rates = default_lease_rates(policy);
	return u16_option(arg, &policy->rates->funding_weight);
}

static char *amount_sat_or_u64_option(const char *arg, u64 *amt)
{
	struct amount_sat sats;
	char *err;

	err = u64_option(arg, amt);
	if (err) {
		tal_free(err);
		if (!parse_amount_sat(&sats, arg, strlen(arg)))
			return tal_fmt(NULL,
				       "Unable to parse option '%s'",
				       arg);

		*amt = sats.satoshis; /* Raw: convert to u64 */
	}

	return NULL;
}

int main(int argc, char **argv)
{
	setup_locale();

	/* Our default funding policy is fixed (0msat) */
	current_policy = default_funder_policy(NULL, FIXED, 0);

	plugin_main(argv, init, PLUGIN_RESTARTABLE, true,
		    NULL,
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs),
		    hooks, ARRAY_SIZE(hooks),
		    NULL, 0,
		    plugin_option("funder-policy",
				  "string",
				  "Policy to use for dual-funding requests."
				  " [match, available, fixed]",
				  funding_option, &current_policy->opt),
		    plugin_option("funder-policy-mod",
				  "string",
				  "Percent to apply policy at"
				  " (match/available); or amount to fund"
				  " (fixed)",
				  amount_sat_or_u64_option,
				  &current_policy->mod),
		    plugin_option("funder-min-their-funding",
				  "string",
				  "Minimum funding peer must open with"
				  " to activate our policy",
				  amount_option,
				  &current_policy->min_their_funding),
		    plugin_option("funder-max-their-funding",
				  "string",
				  "Maximum funding peer may open with"
				  " to activate our policy",
				  amount_option,
				  &current_policy->max_their_funding),
		    plugin_option("funder-per-channel-min",
				  "string",
				  "Minimum funding we'll add to a channel."
				  " If we can't meet this, we don't fund",
				  amount_option,
				  &current_policy->per_channel_min),
		    plugin_option("funder-per-channel-max",
				  "string",
				  "Maximum funding we'll add to a channel."
				  " We cap all contributions to this",
				  amount_option,
				  &current_policy->per_channel_max),
		    plugin_option("funder-reserve-tank",
				  "string",
				  "Amount of funds we'll always leave"
				  " available.",
				  amount_option,
				  &current_policy->reserve_tank),
		    plugin_option("funder-fuzz-percent",
				  "int",
				  "Percent to fuzz the policy contribution by."
				  " Defaults to 5%. Max is 100%",
				  u32_option,
				  &current_policy->fuzz_factor),
		    plugin_option("funder-fund-probability",
				  "int",
				  "Percent of requests to consider."
				  " Defaults to 100%. Setting to 0% will"
				  " disable dual-funding",
				  u32_option,
				  &current_policy->fund_probability),
		    plugin_option("funder-lease-requests-only",
				  "bool",
				  "Only fund lease requests. Defaults to"
				  " true if channel lease rates are"
				  " being advertised",
				  bool_option,
				  &current_policy->leases_only),
		    plugin_option("lease-fee-base-msat",
				  "string",
				  "Channel lease rates, base fee for leased"
				  " funds, in satoshi.",
				  option_lease_fee_base, current_policy),
		    plugin_option("lease-fee-basis",
				  "int",
				  "Channel lease rates, basis charged"
				  " for leased funds (per 10,000 satoshi.)",
				  option_lease_fee_basis, current_policy),
		    plugin_option("lease-funding-weight",
				  "int",
				  "Channel lease rates, weight"
				  " we'll ask opening peer to pay for in"
				  " funding transaction",
				  option_lease_weight_max, current_policy),
		    plugin_option("channel-fee-max-base-msat",
				  "string",
				  "Channel lease rates, maximum channel"
				  " fee base we'll charge for funds"
				  " routed through a leased channel.",
				  option_channel_base, current_policy),
		    plugin_option("channel-fee-max-proportional-thousandths",
				  "int",
				  "Channel lease rates, maximum"
				  " proportional fee (in thousandths, or ppt)"
				  " we'll charge for funds routed through a"
				  " leased channel. Note: 1ppt = 1,000ppm",
				  option_channel_fee_proportional_thousandths_max, current_policy),
		    NULL);

	tal_free(current_policy);
	return 0;
}
