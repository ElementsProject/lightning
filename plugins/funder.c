/* This is a plugin which allows you to specify
 * your policy for accepting/dual-funding incoming
 * v2 channel-open requests.
 *
 */
#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/lease_rates.h>
#include <common/memleak.h>
#include <common/overflows.h>
#include <common/psbt_open.h>
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

/* How much do we need to keep in reserve for anchor spends? */
static struct amount_sat emergency_reserve;

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
unreserve_done(struct command *aux_cmd,
	       const char *buf,
	       const jsmntok_t *result,
	       struct pending_open *open)
{
	plugin_log(open->p, LOG_DBG,
		   "`unreserveinputs` for channel %s completed. %*.s",
		   fmt_channel_id(tmpctx, &open->channel_id),
		   json_tok_full_len(result),
		   json_tok_full(buf, result));

	return aux_command_done(aux_cmd);
}

/* Frees open (eventually, in unreserve_done callback) */
static struct command_result *unreserve_psbt(struct command *cmd,
					     struct pending_open *open)
{
	struct out_req *req;
	struct command *aux;

	plugin_log(open->p, LOG_DBG,
		   "Calling `unreserveinputs` for channel %s",
		   fmt_channel_id(tmpctx,
				  &open->channel_id));

	/* This can outlive the underlying cmd, so use an aux! */
	aux = aux_command(cmd);
	req = jsonrpc_request_start(aux,
				    "unreserveinputs",
				    unreserve_done, unreserve_done,
				    open);
	json_add_psbt(req->js, "psbt", open->psbt);
	send_outreq(req);

	/* We will free this in callback, but remove from list *now*
	 * to avoid calling twice! */
	list_del_from(&pending_opens, &open->list);
	tal_steal(aux, open);

	return command_still_pending(aux);
}

static void cleanup_peer_pending_opens(struct command *cmd,
				       const struct node_id *id)
{
	struct pending_open *i, *next;
	list_for_each_safe(&pending_opens, i, next, list) {
		if (node_id_eq(&i->peer_id, id)) {
			unreserve_psbt(cmd, i);
		}
	}
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
datastore_del_fail(struct command *cmd,
		   const char *buf,
		   const jsmntok_t *error,
		   void *data UNUSED)
{
	/* Eh, ok fine */
	return notification_handled(cmd);
}

static struct command_result *
datastore_del_success(struct command *cmd,
		      const char *buf,
		      const jsmntok_t *result,
		      void *data UNUSED)
{
	/* Cool we deleted some stuff */
	plugin_log(cmd->plugin, LOG_DBG,
		   "`datastore` del succeeded: %*.s",
		   json_tok_full_len(result),
		   json_tok_full(buf, result));

	return notification_handled(cmd);
}

static struct command_result *
datastore_add_fail(struct command *cmd,
		   const char *buf,
		   const jsmntok_t *error,
		   struct wally_psbt *signed_psbt)
{
	/* Oops, something's broken */
	plugin_log(cmd->plugin, LOG_BROKEN,
		   "`datastore` add failed: %*.s",
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	return command_hook_cont_psbt(cmd, signed_psbt);
}

static struct command_result *
datastore_add_success(struct command *cmd,
		      const char *buf,
		      const jsmntok_t *result,
		      struct wally_psbt *signed_psbt)
{
	const char *key, *err;

	err = json_scan(tmpctx, buf, result,
			"{key:%}",
			JSON_SCAN_TAL(cmd, json_strdup, &key));

	if (err)
		plugin_err(cmd->plugin,
			   "`datastore` payload did not scan. %s: %*.s",
			   err, json_tok_full_len(result),
			   json_tok_full(buf, result));

	/* We saved the infos! */
	plugin_log(cmd->plugin, LOG_DBG,
		   "Saved utxos for channel (%s) to datastore",
		   key);

	return command_hook_cont_psbt(cmd, signed_psbt);
}

static struct command_result *
remember_channel_utxos(struct command *cmd,
		       struct pending_open *open,
		       struct wally_psbt *signed_psbt)
{
	struct out_req *req;
	u8 *utxos_bin;
	char *chan_key = tal_fmt(cmd, "funder/%s",
				 fmt_channel_id(cmd,
						&open->channel_id));

	req = jsonrpc_request_start(cmd,
				    "datastore",
				    &datastore_add_success,
				    &datastore_add_fail,
				    signed_psbt);

	utxos_bin = tal_arr(cmd, u8, 0);
	for (size_t i = 0; i < signed_psbt->num_inputs; i++) {
		struct bitcoin_outpoint outpoint;

		/* Don't save peer's UTXOS */
		if (!psbt_input_is_ours(&signed_psbt->inputs[i]))
			continue;

		wally_psbt_input_get_outpoint(&signed_psbt->inputs[i],
					    &outpoint);
		towire_bitcoin_outpoint(&utxos_bin, &outpoint);
	}
	json_add_string(req->js, "key", chan_key);
	/* We either update the existing or add a new one, nbd */
	json_add_string(req->js, "mode", "create-or-replace");
	json_add_hex(req->js, "hex", utxos_bin, tal_bytelen(utxos_bin));
	return send_outreq(req);
}

static struct command_result *
signpsbt_done(struct command *cmd,
	      const char *buf,
	      const jsmntok_t *result,
	      struct pending_open *open)
{
	struct wally_psbt *signed_psbt;
	struct command_result *res;
	const char *err;

	plugin_log(cmd->plugin, LOG_DBG,
		   "`signpsbt` done for channel %s",
		   fmt_channel_id(tmpctx,
				  &open->channel_id));
	err = json_scan(tmpctx, buf, result,
			"{signed_psbt:%}",
			JSON_SCAN_TAL(cmd, json_to_psbt, &signed_psbt));

	if (err)
		plugin_err(cmd->plugin,
			   "`signpsbt` payload did not scan %s: %*.s",
			   err, json_tok_full_len(result),
			   json_tok_full(buf, result));

	/* Save the list of utxos to the datastore! We'll need
	 * them again if we rbf */
	res = remember_channel_utxos(cmd, open, signed_psbt);

	/* The in-flight open is done, let's clean it up! */
	list_del_from(&pending_opens, &open->list);
	tal_free(open);

	return res;
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
			   fmt_channel_id(tmpctx, &cid));
		return command_hook_cont_psbt(cmd, psbt);
	}

	if (!psbt_has_our_input(psbt)) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "no inputs to sign for channel %s",
			   fmt_channel_id(tmpctx, &cid));
		return command_hook_cont_psbt(cmd, psbt);
	}

	plugin_log(cmd->plugin, LOG_DBG,
		   "openchannel_sign PSBT is %s",
		   fmt_wally_psbt(tmpctx, psbt));

	req = jsonrpc_request_start(cmd,
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
		   fmt_channel_id(tmpctx,
				  &open->channel_id), count,
		   count == 1 ? "" : "s");
	return send_outreq(req);
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
		   fmt_wally_psbt(tmpctx, psbt));

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

	/* If this is an RBF, we'll have this */
	struct amount_sat *their_last_funding;
	struct amount_sat *our_last_funding;

	struct amount_sat channel_max;
	u64 funding_feerate_perkw;
	u32 locktime;
	u32 lease_blockheight;
	u32 node_blockheight;

	struct amount_sat requested_lease;

	/* List of previously-used utxos */
	struct bitcoin_outpoint **prev_outs;
};

static struct open_info *new_open_info(const tal_t *ctx)
{
	struct open_info *info = tal(ctx, struct open_info);

	info->their_last_funding = NULL;
	info->our_last_funding = NULL;
	info->requested_lease = AMOUNT_SAT(0);
	info->lease_blockheight = 0;
	info->node_blockheight = 0;
	info->prev_outs = NULL;

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
	json_add_amount_msat(response, "our_funding_msat", our_funding_msat);

	/* If we're accepting an lease request, *and* they've
	 * requested one, fill in our most recent infos */
	if (current_policy->rates && !amount_sat_is_zero(info->requested_lease))
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
		   fmt_amount_sat(tmpctx, info->our_funding),
		   fmt_node_id(tmpctx, &info->id),
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	return command_hook_success(cmd);
}

/* They give msats, we want sats */
static bool json_to_msat_as_sats(const char *buffer, const jsmntok_t *tok,
				 struct amount_sat *sat)
{
	struct amount_msat msat;
	if (!json_to_msat(buffer, tok, &msat))
		return false;
	return amount_msat_to_sat(sat, msat);
}

static struct command_result *param_msat_as_sat(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						struct amount_sat **sat)
{
	struct amount_msat msat;

	*sat = tal(cmd, struct amount_sat);
	if (parse_amount_msat(&msat, buffer + tok->start, tok->end - tok->start)
	    && amount_msat_to_sat(*sat, msat))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a millisatoshi amount");
}

static struct bitcoin_outpoint *
previously_reserved(struct bitcoin_outpoint **prev_outs,
		    struct bitcoin_outpoint *out)
{
	for (size_t i = 0; i < tal_count(prev_outs); i++) {
		if (bitcoin_outpoint_eq(prev_outs[i], out))
			return prev_outs[i];
	}

	return NULL;
}

struct funder_utxo {
	struct bitcoin_outpoint out;
	struct amount_sat val;
};

static struct out_req *
build_utxopsbt_request(struct command *cmd,
		       struct open_info *info,
		       struct bitcoin_outpoint **prev_outs,
		       struct amount_sat requested_funds,
		       struct amount_sat committed_funds,
		       struct funder_utxo **avail_utxos)
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd,
				    "utxopsbt",
				    &psbt_funded,
				    &psbt_fund_failed,
				    info);
	/* Add every prev_out */
	json_array_start(req->js, "utxos");
	for (size_t i = 0; i < tal_count(prev_outs); i++)
		json_add_outpoint(req->js, NULL, prev_outs[i]);

	/* Next add available utxos until we surpass the
	 * requested funds goal */
	/* FIXME: Update `utxopsbt` to automatically add more inputs? */
	for (size_t i = 0; i < tal_count(avail_utxos); i++) {
		/* If we've already hit our goal, break */
		if (amount_sat_greater_eq(committed_funds, requested_funds))
			break;

		/* Add this output to the UTXO */
		json_add_outpoint(req->js, NULL, &avail_utxos[i]->out);

		/* Account for it */
		if (!amount_sat_add(&committed_funds, committed_funds,
				    avail_utxos[i]->val))
			/* This should really never happen */
			plugin_err(cmd->plugin, "overflow adding committed");
	}
	json_array_end(req->js);
	return req;
}

static struct command_result *
listfunds_success(struct command *cmd,
		  const char *buf,
		  const jsmntok_t *result,
		  struct open_info *info)
{
	struct amount_sat available_funds, committed_funds, total_fee;
	const jsmntok_t *outputs_tok, *tok;
	struct out_req *req;
	struct bitcoin_outpoint **avail_prev_outs;
	size_t i;
	const char *funding_err;

	/* We only use this for RBFs, when there's a prev_outs list */
	struct funder_utxo **avail_utxos = tal_arr(cmd, struct funder_utxo *, 0);

	outputs_tok = json_get_member(buf, result, "outputs");
	if (!outputs_tok)
		plugin_err(cmd->plugin,
			   "`listfunds` payload has no outputs token: %*.s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	available_funds = AMOUNT_SAT(0);
	committed_funds = AMOUNT_SAT(0);
	total_fee = AMOUNT_SAT(0);
	avail_prev_outs = tal_arr(info, struct bitcoin_outpoint *, 0);
	json_for_each_arr(i, tok, outputs_tok) {
		struct funder_utxo *utxo;
		struct amount_sat est_fee;
		bool is_reserved;
		struct bitcoin_outpoint *prev_out;
		char *status;
		const char *err;

		utxo = tal(cmd, struct funder_utxo);
		err = json_scan(tmpctx, buf, tok,
				"{amount_msat:%"
				",status:%"
				",reserved:%"
				",txid:%"
				",output:%}",
				JSON_SCAN(json_to_msat_as_sats, &utxo->val),
				JSON_SCAN_TAL(cmd, json_strdup, &status),
				JSON_SCAN(json_to_bool, &is_reserved),
				JSON_SCAN(json_to_txid, &utxo->out.txid),
				JSON_SCAN(json_to_number, &utxo->out.n));
		if (err)
			plugin_err(cmd->plugin,
				   "`listfunds` payload did not scan. %s: %*.s",
				   err, json_tok_full_len(result),
				   json_tok_full(buf, result));

		/* v2 opens don't support p2sh-wrapped inputs */
		if (json_get_member(buf, tok, "redeemscript"))
			continue;

		/* The estimated fee per utxo. */
		est_fee = amount_tx_fee(info->funding_feerate_perkw,
					bitcoin_tx_input_weight(false, 110));

		/* Did we use this utxo on a previous attempt? */
		prev_out = previously_reserved(info->prev_outs, &utxo->out);

		/* we skip reserved funds that aren't in our previous
		 * inputs list! */
		if (is_reserved && !prev_out)
			continue;

		/* we skip unconfirmed+spent funds */
		if (!streq(status, "confirmed"))
			continue;

		/* Don't include outputs that can't cover their weight;
		 *  subtract the fee for this utxo out of the utxo */
		if (!amount_sat_sub(&utxo->val, utxo->val, est_fee))
			continue;

		if (!amount_sat_add(&available_funds, available_funds,
				    utxo->val))
			plugin_err(cmd->plugin,
				   "`listfunds` overflowed output values");

		if (!amount_sat_add(&total_fee, total_fee, est_fee))
			plugin_err(cmd->plugin,
				   "`listfunds` overflowed fee values");

		/* If this is an RBF, we keep track of available utxos */
		if (info->prev_outs) {
			/* if not previously reserved, it's committed */
			if (!prev_out) {
				tal_arr_expand(&avail_utxos, utxo);
				continue;
			}

			if (!amount_sat_add(&committed_funds,
					    committed_funds, utxo->val))
				plugin_err(cmd->plugin,
					   "`listfunds` overflowed"
					   " committed output values");

			/* We also keep a second list of utxos,
			 * as it's possible some utxos got spent
			 * between last attempt + this one! */
			tal_arr_expand(&avail_prev_outs, prev_out);
		}
	}

	/* Even if we don't have an anchor channel yet, we might soon:
	 * keep reserve, even after fee!  Assume two outputs, one for
	 * change. */
	if (!amount_sat_add(&total_fee, total_fee,
			    amount_tx_fee(info->funding_feerate_perkw,
					  BITCOIN_SCRIPTPUBKEY_P2WSH_LEN
					  + change_weight()))) {
		plugin_err(cmd->plugin,
			   "fee value overflow for estimating total fee");
	}

	if (!amount_sat_sub(&available_funds, available_funds, total_fee)
	    || !amount_sat_sub(&available_funds, available_funds, emergency_reserve))
		available_funds = AMOUNT_SAT(0);

	funding_err = calculate_our_funding(current_policy,
					    info->id,
					    info->their_funding,
					    info->our_last_funding,
					    available_funds,
					    info->channel_max,
					    info->requested_lease,
					    &info->our_funding);
	plugin_log(cmd->plugin, LOG_DBG,
		   "Policy %s returned funding amount of %s. %s",
		   funder_policy_desc(tmpctx, current_policy),
		   fmt_amount_sat(tmpctx, info->our_funding),
		   funding_err ? funding_err : "");

	if (amount_sat_is_zero(info->our_funding))
		return command_hook_success(cmd);

	plugin_log(cmd->plugin, LOG_DBG,
		   "Funding channel %s with %s (their input %s)",
		   fmt_channel_id(tmpctx, &info->cid),
		   fmt_amount_sat(tmpctx, info->our_funding),
		   fmt_amount_sat(tmpctx, info->their_funding));

	/* If there's prevouts, we compose a psbt with those first,
	 * then add more funds for anything missing */
	if (info->prev_outs) {
		req = build_utxopsbt_request(cmd, info,
					     avail_prev_outs,
					     info->our_funding,
					     committed_funds,
					     avail_utxos);
		json_add_bool(req->js, "reservedok", true);
		/* We don't re-reserve any UTXOS :) */
		json_add_num(req->js, "reserve", 0);
	} else {
		req = jsonrpc_request_start(cmd,
					    "fundpsbt",
					    &psbt_funded,
					    &psbt_fund_failed,
					    info);

		json_add_bool(req->js, "nonwrapped", true);
	}
	json_add_string(req->js, "satoshi",
			fmt_amount_sat(tmpctx, info->our_funding));
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

	return send_outreq(req);
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
		   fmt_node_id(tmpctx,
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
	struct open_info *info = new_open_info(cmd);
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
			",their_funding_msat:%"
			",max_htlc_value_in_flight_msat:%"
			",htlc_minimum_msat:%"
			",funding_feerate_per_kw:%"
			",commitment_feerate_per_kw:%"
			",feerate_our_max:%"
			",feerate_our_min:%"
			",to_self_delay:%"
			",max_accepted_htlcs:%"
			",channel_flags:%"
			",locktime:%"
			",channel_max_msat:%}}",
			JSON_SCAN(json_to_node_id, &info->id),
			JSON_SCAN(json_to_channel_id, &info->cid),
			JSON_SCAN(json_to_msat_as_sats, &info->their_funding),
			JSON_SCAN(json_to_msat, &max_htlc_inflight),
			JSON_SCAN(json_to_msat, &htlc_minimum),
			JSON_SCAN(json_to_u64, &info->funding_feerate_perkw),
			JSON_SCAN(json_to_u64, &commitment_feerate_perkw),
			JSON_SCAN(json_to_u64, &feerate_our_max),
			JSON_SCAN(json_to_u64, &feerate_our_min),
			JSON_SCAN(json_to_u32, &to_self_delay),
			JSON_SCAN(json_to_u32, &max_accepted_htlcs),
			JSON_SCAN(json_to_u16, &channel_flags),
			JSON_SCAN(json_to_u32, &info->locktime),
			JSON_SCAN(json_to_msat_as_sats, &info->channel_max));

	if (err)
		plugin_err(cmd->plugin,
			   "`openchannel2` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* Channel lease info isn't necessarily included, ignore any err */
	json_scan(tmpctx, buf, params,
		  "{openchannel2:{"
		  "requested_lease_msat:%"
		  ",lease_blockheight_start:%"
		  ",node_blockheight:%}}",
		  JSON_SCAN(json_to_msat_as_sats, &info->requested_lease),
		  JSON_SCAN(json_to_u32, &info->lease_blockheight),
		  JSON_SCAN(json_to_u32, &info->node_blockheight));

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
	    !amount_sat_is_zero(info->requested_lease)) {
		struct json_stream *res = jsonrpc_stream_success(cmd);
		json_add_string(res, "result", "reject");
		json_add_string(res, "error_message",
				"Peer requested funds but we're not advertising"
				" liquidity right now");
		return command_finished(cmd, res);
	}


	/* Check that their block height isn't too far behind */
	if (!amount_sat_is_zero(info->requested_lease)) {
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
	req = jsonrpc_request_start(cmd,
				    "listfunds",
				    &listfunds_success,
				    &listfunds_failed,
				    info);

	return send_outreq(req);
}

static struct command_result *
datastore_list_fail(struct command *cmd,
		    const char *buf,
		    const jsmntok_t *error,
		    struct open_info *info)
{
	struct out_req *req;

	/* Oops, something's broken */
	plugin_log(cmd->plugin, LOG_BROKEN,
		   "`datastore` list failed: %*.s",
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	/* Figure out what our funds are... same flow
	 * as with openchannel2 callback.  */
	req = jsonrpc_request_start(cmd,
				    "listfunds",
				    &listfunds_success,
				    &listfunds_failed,
				    info);
	return send_outreq(req);
}

static struct command_result *
datastore_list_success(struct command *cmd,
		       const char *buf,
		       const jsmntok_t *result,
		       struct open_info *info)
{
	struct out_req *req;
	const char *key, *err;
	const u8 *utxos_bin;
	size_t len, i;
	const jsmntok_t *ds_arr_tok, *ds_result;

	ds_arr_tok = json_get_member(buf, result, "datastore");
	assert(ds_arr_tok->type == JSMN_ARRAY);

	/* There should only be one result */
	utxos_bin = NULL;
	json_for_each_arr(i, ds_result, ds_arr_tok) {
		err = json_scan(tmpctx, buf, ds_result,
				"{key:%,hex:%}",
				JSON_SCAN_TAL(cmd, json_strdup, &key),
				JSON_SCAN_TAL(cmd, json_tok_bin_from_hex,
					      &utxos_bin));

		if (err)
			plugin_err(cmd->plugin,
				   "`listdatastore` payload did"
				   " not scan. %s: %*.s",
				   err, json_tok_full_len(result),
				   json_tok_full(buf, result));

		/* We found the prev utxo list */
		plugin_log(cmd->plugin, LOG_DBG,
			   "Saved utxos for channel (%s)"
			   " pulled from datastore", key);

		/* There should only be one result */
		break;
	}

	/* Resurrect outpoints from stashed binary */
	len = tal_bytelen(utxos_bin);
	while (len > 0) {
		struct bitcoin_outpoint *outpoint =
			tal(info, struct bitcoin_outpoint);
		fromwire_bitcoin_outpoint(&utxos_bin,
					  &len, outpoint);
		/* Cursor gets set to null if above fails */
		if (!utxos_bin)
			plugin_err(cmd->plugin,
				   "Unable to parse saved utxos: %.*s",
				   json_tok_full_len(result),
				   json_tok_full(buf, result));

		if (!info->prev_outs)
			info->prev_outs =
				tal_arr(info, struct bitcoin_outpoint *, 0);

		tal_arr_expand(&info->prev_outs, outpoint);
	}

	req = jsonrpc_request_start(cmd,
				    "listfunds",
				    &listfunds_success,
				    &listfunds_failed,
				    info);
	return send_outreq(req);
}

/* Peer has asked us to RBF */
static struct command_result *
json_rbf_channel_call(struct command *cmd,
		      const char *buf,
		      const jsmntok_t *params)
{
	struct open_info *info = new_open_info(cmd);
	u64 feerate_our_max, feerate_our_min;
	const char *err, *chan_key;
	struct out_req *req;

	info->their_last_funding = tal(info, struct amount_sat);
	info->our_last_funding = tal(info, struct amount_sat);
	err = json_scan(tmpctx, buf, params,
			"{rbf_channel:"
			"{id:%"
			",channel_id:%"
			",their_last_funding_msat:%"
			",their_funding_msat:%"
			",our_last_funding_msat:%"
			",funding_feerate_per_kw:%"
			",feerate_our_max:%"
			",feerate_our_min:%"
			",locktime:%"
			",channel_max_msat:%}}",
			JSON_SCAN(json_to_node_id, &info->id),
			JSON_SCAN(json_to_channel_id, &info->cid),
			JSON_SCAN(json_to_msat_as_sats,
				  info->their_last_funding),
			JSON_SCAN(json_to_msat_as_sats,
				  &info->their_funding),
			JSON_SCAN(json_to_msat_as_sats,
				  info->our_last_funding),
			JSON_SCAN(json_to_u64, &info->funding_feerate_perkw),
			JSON_SCAN(json_to_u64, &feerate_our_max),
			JSON_SCAN(json_to_u64, &feerate_our_min),
			JSON_SCAN(json_to_u32, &info->locktime),
			JSON_SCAN(json_to_msat_as_sats, &info->channel_max));

	if (err)
		plugin_err(cmd->plugin,
			   "`rbf_channel` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* Lease info isn't necessarily included, ignore any err */
	/* FIXME: blockheights?? */
	json_scan(tmpctx, buf, params,
		  "{rbf_channel:{"
		  "requested_lease_msat:%}}",
		  JSON_SCAN(json_to_msat_as_sats, &info->requested_lease));

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

	/* Fetch out previous utxos from the datastore */
	req = jsonrpc_request_start(cmd,
				    "listdatastore",
				    &datastore_list_success,
				    &datastore_list_fail,
				    info);
	chan_key = tal_fmt(cmd, "funder/%s",
			   fmt_channel_id(cmd,
					  &info->cid));
	json_add_string(req->js, "key", chan_key);
	return send_outreq(req);
}

static struct command_result *json_disconnect(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *params)
{
	struct node_id id;
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{disconnect:{id:%}}",
			JSON_SCAN(json_to_node_id, &id));
	if (err)
		plugin_err(cmd->plugin,
			   "`disconnect` notification payload did not"
			   " scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	plugin_log(cmd->plugin, LOG_DBG,
		   "Cleaning up inflights for peer id %s",
		   fmt_node_id(tmpctx, &id));

	cleanup_peer_pending_opens(cmd, &id);

	return notification_handled(cmd);
}

static struct command_result *
delete_channel_from_datastore(struct command *cmd,
			      struct channel_id *cid)
{
	const struct out_req *req;

	/* Fetch out previous utxos from the datastore.
	 * If we were clever, we'd have some way of tracking
	 * channels that we actually might have data for
	 * but this is much easier */
	req = jsonrpc_request_start(cmd,
				    "deldatastore",
				    &datastore_del_success,
				    &datastore_del_fail,
				    NULL);
	json_add_string(req->js, "key",
			tal_fmt(cmd, "funder/%s",
				fmt_channel_id(cmd, cid)));
	return send_outreq(req);
}

static struct command_result *json_channel_state_changed(struct command *cmd,
							 const char *buf,
							 const jsmntok_t *params)
{
	struct channel_id cid;
	const char *err, *old_state, *new_state;

	err = json_scan(tmpctx, buf, params,
			"{channel_state_changed:"
			"{channel_id:%"
			",old_state:%"
			",new_state:%}}",
			JSON_SCAN(json_to_channel_id, &cid),
			JSON_SCAN_TAL(cmd, json_strdup, &old_state),
			JSON_SCAN_TAL(cmd, json_strdup, &new_state));

	if (err)
		plugin_err(cmd->plugin,
			   "`channel_state_changed` notification payload did"
			   " not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* Moving out of "awaiting lockin",
	 * means we clean up the datastore */
	/* FIXME: splicing state? */
	if (!streq(old_state, "DUALOPEND_AWAITING_LOCKIN")
	    && !streq(old_state, "CHANNELD_AWAITING_LOCKIN"))
		return notification_handled(cmd);

	plugin_log(cmd->plugin, LOG_DBG,
		   "Cleaning up datastore for channel_id %s",
		   fmt_channel_id(tmpctx, &cid));

	return delete_channel_from_datastore(cmd, &cid);
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
		   fmt_channel_id(tmpctx, &cid));

	open = find_channel_pending_open(&cid);
	if (open)
		unreserve_psbt(cmd, open);

	/* Also clean up datastore for this channel */
	return delete_channel_from_datastore(cmd, &cid);
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
	json_add_amount_sat_msat(stream, "min_their_funding_msat",
				 policy->min_their_funding);
	json_add_amount_sat_msat(stream, "max_their_funding_msat",
				 policy->max_their_funding);
	json_add_amount_sat_msat(stream, "per_channel_min_msat",
				 policy->per_channel_min);
	json_add_amount_sat_msat(stream, "per_channel_max_msat",
				 policy->per_channel_max);
	json_add_amount_sat_msat(stream, "reserve_tank_msat",
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

	err = funding_option(cmd->plugin, opt_str, false, *opt);
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

	err = u64_option(cmd->plugin, arg_str, false, *mod);
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
		   p_opt_def("min_their_funding_msat", param_msat_as_sat,
			     &min_their_funding,
			     current_policy->min_their_funding),
		   p_opt_def("max_their_funding_msat", param_msat_as_sat,
			     &max_their_funding,
			     current_policy->max_their_funding),
		   p_opt_def("per_channel_min_msat", param_msat_as_sat,
			     &per_channel_min,
			     current_policy->per_channel_min),
		   p_opt_def("per_channel_max_msat", param_msat_as_sat,
			     &per_channel_max,
			     current_policy->per_channel_max),
		   p_opt_def("reserve_tank_msat", param_msat_as_sat, &reserve_tank,
			     current_policy->reserve_tank),
		   p_opt_def("fuzz_percent", param_number,
			     &fuzz_factor,
			     current_policy->fuzz_factor),
		   p_opt_def("fund_probability", param_number,
			     &fund_probability,
			     current_policy->fund_probability),
		   p_opt("lease_fee_base_msat", param_msat_as_sat, &lease_fee_sats),
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
	req = jsonrpc_request_start(cmd,
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

	return send_outreq(req);
}

static const struct plugin_command commands[] = {
	{
		"funderupdate",
		json_funderupdate
	},
};

static void tell_lightningd_lease_rates(struct command *init_cmd,
					struct lease_rates *rates)
{
	struct json_out *jout;
	struct amount_msat mval;

	/* Tell lightningd with our lease rates*/
	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');

	mval = amount_msat(rates->lease_fee_base_sat * 1000);
	json_out_addstr(jout, "lease_fee_base_msat",
			fmt_amount_msat(tmpctx, mval));
	json_out_add(jout, "lease_fee_basis", false,
		     "%d", rates->lease_fee_basis);

	json_out_add(jout, "funding_weight", false,
		     "%d", rates->funding_weight);

	mval = amount_msat(rates->channel_fee_max_base_msat);
	json_out_addstr(jout, "channel_fee_max_base_msat",
			fmt_amount_msat(tmpctx, mval));
	json_out_add(jout, "channel_fee_max_proportional_thousandths", false,
		     "%d", rates->channel_fee_max_proportional_thousandths);

	json_out_end(jout, '}');
	json_out_finished(jout);

	rpc_scan(init_cmd, "setleaserates", take(jout),
		 /* Unused */
		 "{lease_fee_base_msat:%}",
		 JSON_SCAN(json_to_msat, &mval));

}

static void memleak_mark(struct plugin *p, struct htable *memtable)
{
	memleak_scan_list_head(memtable, &pending_opens);
	memleak_scan_obj(memtable, current_policy);
}

static const char *init(struct command *init_cmd, const char *b, const jsmntok_t *t)
{
	const char *err;
	struct amount_msat msat;

	list_head_init(&pending_opens);

	err = funder_check_policy(current_policy);
	if (err)
		plugin_err(init_cmd->plugin, "Invalid parameter combination: %s", err);

	if (current_policy->rates)
		tell_lightningd_lease_rates(init_cmd, current_policy->rates);

	rpc_scan(init_cmd, "listconfigs",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{configs:"
		 "{min-emergency-msat:{value_msat:%}}}",
		 JSON_SCAN(json_to_msat, &msat));

	emergency_reserve = amount_msat_to_sat_round_down(msat);
	plugin_set_memleak_handler(init_cmd->plugin, memleak_mark);

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
	{
		"channel_state_changed",
		json_channel_state_changed,
	},
};

static char *option_channel_base(struct plugin *plugin, const char *arg,
				 bool check_only, struct funder_policy *policy)
{
	struct amount_msat amt;
	u32 cfmbm;

	if (!parse_amount_msat(&amt, arg, strlen(arg)))
		return tal_fmt(tmpctx, "Unable to parse amount '%s'", arg);

	if (!assign_overflow_u32(&cfmbm, amt.millisatoshis)) /* Raw: conversion */
		return tal_fmt(tmpctx, "channel_fee_max_base_msat overflowed");

	if (!check_only) {
		if (!policy->rates)
			policy->rates = default_lease_rates(policy);
		policy->rates->channel_fee_max_base_msat = cfmbm;
	}

	return NULL;
}

static char *
option_channel_fee_proportional_thousandths_max(struct plugin *plugin,
						const char *arg,
						bool check_only,
						struct funder_policy *policy)
{
	u16 fptm;
	char *problem = u16_option(plugin, arg, false, &fptm);

	if (problem || check_only)
		return problem;

	if (!policy->rates)
		policy->rates = default_lease_rates(policy);
	policy->rates->channel_fee_max_proportional_thousandths = fptm;
	return NULL;
}

static char *amount_option(struct plugin *plugin, const char *arg, bool check_only,
			   struct amount_sat *amt)
{
	struct amount_sat v;
	if (!parse_amount_sat(&v, arg, strlen(arg)))
		return tal_fmt(tmpctx, "Unable to parse amount '%s'", arg);

	if (!check_only)
		*amt = v;
	return NULL;
}

static bool jsonfmt_amount_sat(struct plugin *plugin,
			       struct json_stream *js,
			       const char *fieldname,
			       struct amount_sat *sats)
{
	/* We do not expose raw numbers for sats fields: raw numbers
	 * in our interface means MSAT! */
	json_add_str_fmt(js, fieldname, "%"PRIu64"sat", sats->satoshis /* Raw: fmt */);
	return true;
}

static char *option_lease_fee_base(struct plugin *plugin, const char *arg,
				   bool check_only,
				   struct funder_policy *policy)
{
	struct amount_sat amt;
	u32 lfbs;
	char *err;

	err = amount_option(plugin, arg, false, &amt);
	if (err)
		return err;

	if (!assign_overflow_u32(&lfbs, amt.satoshis)) /* Raw: conversion */
		return tal_fmt(tmpctx, "lease_fee_base_sat overflowed");

	if (!check_only) {
		if (!policy->rates)
			policy->rates = default_lease_rates(policy);

		policy->rates->lease_fee_base_sat = lfbs;
	}

	return NULL;
}

static char *option_lease_fee_basis(struct plugin *plugin, const char *arg,
				    bool check_only,
				    struct funder_policy *policy)
{
	u16 lfb;
	char *problem = u16_option(plugin, arg, false, &lfb);

	if (problem || check_only)
		return problem;

	if (!policy->rates)
		policy->rates = default_lease_rates(policy);
	policy->rates->lease_fee_basis = lfb;
	return NULL;
}

static char *option_lease_weight_max(struct plugin *plugin, const char *arg,
				     bool check_only,
				     struct funder_policy *policy)
{
	u16 fw;
	char *problem = u16_option(plugin, arg, false, &fw);

	if (problem || check_only)
		return problem;

	if (!policy->rates)
		policy->rates = default_lease_rates(policy);
	policy->rates->funding_weight = fw;
	return NULL;
}

static char *amount_sat_or_u64_option(struct plugin *plugin,
				      const char *arg,
				      bool check_only,
				      u64 *amt)
{
	struct amount_sat sats;
	char *err;

	err = u64_option(plugin, arg, false, &sats.satoshis); /* Raw: want sats below */
	if (err) {
		tal_free(err);
		if (!parse_amount_sat(&sats, arg, strlen(arg)))
			return tal_fmt(tmpctx,
				       "Unable to parse option '%s'",
				       arg);
	}

	if (!check_only)
		*amt = sats.satoshis; /* Raw: convert to u64 */

	return NULL;
}

static bool jsonfmt_policy_mod(struct plugin *plugin,
			       struct json_stream *js,
			       const char *fieldname,
			       u64 *amt)
{
	json_add_u64(js, fieldname, *amt);
	return true;
}

int main(int argc, char **argv)
{
	setup_locale();

	/* Our default funding policy is fixed (0msat) */
	current_policy = default_funder_policy(NULL, FIXED, 0);

	plugin_main(argv, init, NULL, PLUGIN_RESTARTABLE, true,
		    NULL,
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs),
		    hooks, ARRAY_SIZE(hooks),
		    NULL, 0,
		    plugin_option("funder-policy",
				  "string",
				  "Policy to use for dual-funding requests."
				  " [match, available, fixed]",
				  funding_option,
				  jsonfmt_funding_option,
				  &current_policy->opt),
		    plugin_option("funder-policy-mod",
				  "string",
				  "Percent to apply policy at"
				  " (match/available); or amount to fund"
				  " (fixed)",
				  amount_sat_or_u64_option,
				  jsonfmt_policy_mod,
				  &current_policy->mod),
		    plugin_option("funder-min-their-funding",
				  "string",
				  "Minimum funding peer must open with"
				  " to activate our policy",
				  amount_option,
				  jsonfmt_amount_sat,
				  &current_policy->min_their_funding),
		    plugin_option("funder-max-their-funding",
				  "string",
				  "Maximum funding peer may open with"
				  " to activate our policy",
				  amount_option,
				  jsonfmt_amount_sat,
				  &current_policy->max_their_funding),
		    plugin_option("funder-per-channel-min",
				  "string",
				  "Minimum funding we'll add to a channel."
				  " If we can't meet this, we don't fund",
				  amount_option,
				  jsonfmt_amount_sat,
				  &current_policy->per_channel_min),
		    plugin_option("funder-per-channel-max",
				  "string",
				  "Maximum funding we'll add to a channel."
				  " We cap all contributions to this",
				  amount_option,
				  jsonfmt_amount_sat,
				  &current_policy->per_channel_max),
		    plugin_option("funder-reserve-tank",
				  "string",
				  "Amount of funds we'll always leave"
				  " available.",
				  amount_option,
				  jsonfmt_amount_sat,
				  &current_policy->reserve_tank),
		    plugin_option("funder-fuzz-percent",
				  "int",
				  "Percent to fuzz the policy contribution by."
				  " Defaults to 0%. Max is 100%",
				  u32_option, u32_jsonfmt,
				  &current_policy->fuzz_factor),
		    plugin_option("funder-fund-probability",
				  "int",
				  "Percent of requests to consider."
				  " Defaults to 100%. Setting to 0% will"
				  " disable dual-funding",
				  u32_option, u32_jsonfmt,
				  &current_policy->fund_probability),
		    plugin_option("funder-lease-requests-only",
				  "bool",
				  "Only fund lease requests. Defaults to"
				  " true if channel lease rates are"
				  " being advertised",
				  bool_option, bool_jsonfmt,
				  &current_policy->leases_only),
		    plugin_option("lease-fee-base-sat",
				  "string",
				  "Channel lease rates, base fee for leased"
				  " funds, in satoshi.",
				  option_lease_fee_base,
				  NULL,
				  current_policy),
		    plugin_option("lease-fee-basis",
				  "int",
				  "Channel lease rates, basis charged"
				  " for leased funds (per 10,000 satoshi.)",
				  option_lease_fee_basis,
				  NULL,
				  current_policy),
		    plugin_option("lease-funding-weight",
				  "int",
				  "Channel lease rates, weight"
				  " we'll ask opening peer to pay for in"
				  " funding transaction",
				  option_lease_weight_max,
				  NULL,
				  current_policy),
		    plugin_option("channel-fee-max-base-msat",
				  "string",
				  "Channel lease rates, maximum channel"
				  " fee base we'll charge for funds"
				  " routed through a leased channel.",
				  option_channel_base,
				  NULL,
				  current_policy),
		    plugin_option("channel-fee-max-proportional-thousandths",
				  "int",
				  "Channel lease rates, maximum"
				  " proportional fee (in thousandths, or ppt)"
				  " we'll charge for funds routed through a"
				  " leased channel. Note: 1ppt = 1,000ppm",
				  option_channel_fee_proportional_thousandths_max,
				  NULL,
				  current_policy),
		    NULL);

	tal_free(current_policy);
	return 0;
}
