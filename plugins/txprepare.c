#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <common/addr.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/psbt_open.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <plugins/libplugin.h>
#include <wally_psbt.h>

struct tx_output {
	struct amount_sat amount;
	const u8 *script;
	bool is_to_external;
};

struct txprepare {
	struct tx_output *outputs;
	struct amount_sat output_total;
	/* Weight for core + outputs */
	size_t weight;

	/* Which output is 'all', or -1 (not counted in output_total!) */
	int all_output_idx;

	/* Once we have a PSBT, it goes here. */
	struct wally_psbt *psbt;
	u32 feerate;

	/* For withdraw, we actually send immediately. */
	bool is_withdraw;

	/* Keep track if upgrade, so we can report on finish */
	bool is_upgrade;
};

struct unreleased_tx {
	struct list_node list;
	struct bitcoin_txid txid;
	struct wally_tx *tx;
	struct wally_psbt *psbt;
	bool is_upgrade;
};

static LIST_HEAD(unreleased_txs);

static struct wally_psbt *json_tok_psbt(const tal_t *ctx,
					const char *buffer,
					const jsmntok_t *tok)
{
	return psbt_from_b64(ctx, buffer + tok->start, tok->end - tok->start);
}

static struct command_result *param_outputs(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    struct txprepare *txp)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Expected an array of outputs in the "
				    "format '[{\"txid\":0}, ...]', got \"%s\"",
				    json_strdup(tmpctx, buffer, tok));
	}

	txp->outputs = tal_arr(txp, struct tx_output, tok->size);
	txp->output_total = AMOUNT_SAT(0);
	txp->all_output_idx = -1;

	/* We assume < 253 inputs, and if we're wrong, the fee
	 * difference is trivial. */
	txp->weight = bitcoin_tx_core_weight(1, tal_count(txp->outputs));

	json_for_each_arr(i, t, tok) {
		enum address_parse_result res;
		struct tx_output *out = &txp->outputs[i];

		/* We assume these are accounted for elsewhere */
		out->is_to_external = false;

		/* output format: {destination: amount} */
		if (t->type != JSMN_OBJECT)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "The output format must be "
					    "{destination: amount}");
		res = json_to_address_scriptpubkey(cmd,
 						   chainparams,
						   buffer, &t[1],
						   &out->script);
		if (res == ADDRESS_PARSE_UNRECOGNIZED)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not parse destination address");
		else if (res == ADDRESS_PARSE_WRONG_NETWORK)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Destination address is not on network %s",
					    chainparams->network_name);

		if (!json_to_sat_or_all(buffer, &t[2], &out->amount))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "'%.*s' is a invalid satoshi amount",
					    t[2].end - t[2].start,
					    buffer + t[2].start);

		if (amount_sat_eq(out->amount, AMOUNT_SAT(-1ULL))) {
			if (txp->all_output_idx != -1)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Cannot use 'all' in"
						    " two outputs");
			txp->all_output_idx = i;
		} else {
			if (!amount_sat_add(&txp->output_total,
					    txp->output_total,
					    out->amount))
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Output amount overflow");
		}
		txp->weight += bitcoin_tx_output_weight(tal_bytelen(out->script));
	}
	return NULL;
}

/* Called after lightningd has broadcast the transaction. */
static struct command_result *sendpsbt_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct unreleased_tx *utx)
{
	struct json_stream *out;

	out = jsonrpc_stream_success(cmd);
	json_add_hex_talarr(out, "tx", linearize_wtx(tmpctx, utx->tx));
	json_add_txid(out, "txid", &utx->txid);
	json_add_psbt(out, "psbt", utx->psbt);
	if (utx->is_upgrade)
		json_add_num(out, "upgraded_outs", utx->tx->num_inputs);
	return command_finished(cmd, out);
}

/* Called after lightningd has signed the inputs. */
static struct command_result *signpsbt_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct unreleased_tx *utx)
{
	struct out_req *req;
	const jsmntok_t *psbttok = json_get_member(buf, result, "signed_psbt");
	struct bitcoin_txid txid;

	tal_free(utx->psbt);
	utx->psbt = json_tok_psbt(utx, buf, psbttok);
	/* Replace with signed tx. */
	tal_free(utx->tx);

	/* The txid from the final should match our expectation. */
	psbt_txid(utx, utx->psbt, &txid, &utx->tx);
	if (!bitcoin_txid_eq(&txid, &utx->txid)) {
		return command_fail(cmd, LIGHTNINGD,
				    "Signed tx changed txid? Had '%s' now '%s'",
				    tal_hex(tmpctx,
					    linearize_wtx(tmpctx, utx->tx)),
				    type_to_string(tmpctx, struct wally_psbt,
                           utx->psbt));
	}

	req = jsonrpc_request_start(cmd->plugin, cmd, "sendpsbt",
				    sendpsbt_done, forward_error,
				    utx);
	json_add_psbt(req->js, "psbt", utx->psbt);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *finish_txprepare(struct command *cmd,
					       struct txprepare *txp)
{
	struct json_stream *js;
	struct unreleased_tx *utx;

	/* Add the outputs they gave us */
	for (size_t i = 0; i < tal_count(txp->outputs); i++) {
		struct wally_tx_output *out;

		out = wally_tx_output(NULL, txp->outputs[i].script,
				      txp->outputs[i].amount);
		if (!out)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid output %zi (%s:%s)", i,
					    tal_hex(tmpctx,
						    txp->outputs[i].script),
					    type_to_string(tmpctx,
							   struct amount_sat,
							   &txp->outputs[i].amount));
		psbt_add_output(txp->psbt, out, i);

		if (txp->outputs[i].is_to_external)
			psbt_output_mark_as_external(txp->psbt,
						     &txp->psbt->outputs[i]);

		wally_tx_output_free(out);
	}

	/* If this is elements, we should normalize
	 * the PSBT fee output */
	psbt_elements_normalize_fees(txp->psbt);

	utx = tal(NULL, struct unreleased_tx);
	utx->is_upgrade = txp->is_upgrade;
	utx->psbt = tal_steal(utx, txp->psbt);
	psbt_txid(utx, utx->psbt, &utx->txid, &utx->tx);

	/* If this is a withdraw, we sign and send immediately. */
	if (txp->is_withdraw) {
		struct out_req *req;

		/* Won't live beyond this cmd. */
		tal_steal(cmd, utx);
		req = jsonrpc_request_start(cmd->plugin, cmd, "signpsbt",
					    signpsbt_done, forward_error,
					    utx);
		json_add_psbt(req->js, "psbt", utx->psbt);
		return send_outreq(cmd->plugin, req);
	}

	list_add(&unreleased_txs, &utx->list);
	js = jsonrpc_stream_success(cmd);
	json_add_hex_talarr(js, "unsigned_tx", linearize_wtx(tmpctx, utx->tx));
	json_add_txid(js, "txid", &utx->txid);
	json_add_psbt(js, "psbt", utx->psbt);
	return command_finished(cmd, js);
}

/* fundpsbt/utxopsbt gets a viable PSBT for us. */
static struct command_result *psbt_created(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *result,
					   struct txprepare *txp)
{
	const jsmntok_t *psbttok;
	struct amount_msat excess_msat;
	struct amount_sat excess;
	u32 weight;

	psbttok = json_get_member(buf, result, "psbt");
	txp->psbt = json_tok_psbt(txp, buf, psbttok);
	if (!txp->psbt)
		return command_fail(cmd, LIGHTNINGD,
				    "Unparsable psbt: '%.*s'",
				    psbttok->end - psbttok->start,
				    buf + psbttok->start);

	if (!psbt_set_version(txp->psbt, 2)) {
		return command_fail(cmd, LIGHTNINGD,
					"Unable to convert PSBT to version 2.");
	}

	if (!json_to_number(buf, json_get_member(buf, result, "feerate_per_kw"),
			    &txp->feerate))
		return command_fail(cmd, LIGHTNINGD,
				    "Unparsable feerate_per_kw: '%.*s'",
				    result->end - result->start,
				    buf + result->start);

	if (!json_to_msat(buf, json_get_member(buf, result, "excess_msat"),
			  &excess_msat)
	    || !amount_msat_to_sat(&excess, excess_msat))
		return command_fail(cmd, LIGHTNINGD,
				    "Unparsable excess_msat: '%.*s'",
				    result->end - result->start,
				    buf + result->start);

	if (!json_to_number(buf, json_get_member(buf, result,
						 "estimated_final_weight"),
			    &weight))
		return command_fail(cmd, LIGHTNINGD,
				    "Unparsable estimated_final_weight: '%.*s'",
				    result->end - result->start,
				    buf + result->start);

	/* If we have an "all" output, we now know its value ("excess_msat") */
	if (txp->all_output_idx != -1) {
		txp->outputs[txp->all_output_idx].amount = excess;
	}

	return finish_txprepare(cmd, txp);
}

/* Common point for txprepare and withdraw */
static struct command_result *txprepare_continue(struct command *cmd,
						 struct txprepare *txp,
						 const char *feerate,
						 unsigned int *minconf,
						 struct bitcoin_outpoint *utxos,
						 bool is_withdraw,
						 bool reservedok)
{
	struct out_req *req;

	txp->is_withdraw = is_withdraw;

	/* p_opt_def doesn't compile with strings... */
	if (!feerate)
		feerate = "opening";

	/* These calls are deliberately very similar, but utxopsbt wants utxos,
	 * and fundpsbt wants minconf */
	if (utxos) {
		req = jsonrpc_request_start(cmd->plugin, cmd, "utxopsbt",
					    psbt_created, forward_error,
					    txp);
		json_array_start(req->js, "utxos");
		for (size_t i = 0; i < tal_count(utxos); i++) {
			json_add_outpoint(req->js, NULL, &utxos[i]);
		}
		json_array_end(req->js);
		json_add_bool(req->js, "reservedok", reservedok);
	} else {
		req = jsonrpc_request_start(cmd->plugin, cmd, "fundpsbt",
					    psbt_created, forward_error,
					    txp);
		if (minconf)
			json_add_u32(req->js, "minconf", *minconf);
	}

	if (txp->all_output_idx == -1)
		json_add_sats(req->js, "satoshi", txp->output_total);
	else
		json_add_string(req->js, "satoshi", "all");

	json_add_u32(req->js, "startweight", txp->weight);
	json_add_bool(req->js, "excess_as_change", true);

	json_add_string(req->js, "feerate", feerate);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_txprepare(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *params)
{
	struct txprepare *txp = tal(cmd, struct txprepare);
	const char *feerate;
	struct bitcoin_outpoint *utxos;
	unsigned int *minconf;

	if (!param(cmd, buffer, params,
		   p_req("outputs", param_outputs, txp),
		   p_opt("feerate", param_string, &feerate),
		   p_opt_def("minconf", param_number, &minconf, 1),
		   p_opt("utxos", param_outpoint_arr, &utxos),
		   NULL))
		return command_param_failed();

	txp->is_upgrade = false;
	return txprepare_continue(cmd, txp, feerate, minconf, utxos, false, false);
}

/* Called after we've unreserved the inputs. */
static struct command_result *unreserve_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct unreleased_tx *utx)
{
	struct json_stream *out;

	out = jsonrpc_stream_success(cmd);
	json_add_hex_talarr(out, "unsigned_tx", linearize_wtx(tmpctx, utx->tx));
	json_add_txid(out, "txid", &utx->txid);

	return command_finished(cmd, out);
}

static struct command_result *param_unreleased_txid(struct command *cmd,
						    const char *name,
						    const char *buffer,
						    const jsmntok_t *tok,
						    struct unreleased_tx **utx)
{
	struct command_result *res;
	struct bitcoin_txid *txid;

	res = param_txid(cmd, name, buffer, tok, &txid);
	if (res)
		return res;

	list_for_each(&unreleased_txs, (*utx), list) {
		if (bitcoin_txid_eq(txid, &(*utx)->txid))
			return NULL;
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "not an unreleased txid '%s'",
			    type_to_string(tmpctx, struct bitcoin_txid, txid));
}

static struct command_result *json_txdiscard(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *params)
{
	struct unreleased_tx *utx;
	struct out_req *req;

	if (!param(cmd, buffer, params,
		   p_req("txid", param_unreleased_txid, &utx),
		   NULL))
		return command_param_failed();

	/* Remove from list now, to avoid races! */
	list_del_from(&unreleased_txs, &utx->list);
	/* Whatever happens, we free it once this command is done. */
	tal_steal(cmd, utx);

	req = jsonrpc_request_start(cmd->plugin, cmd, "unreserveinputs",
				    unreserve_done, forward_error,
				    utx);
	json_add_psbt(req->js, "psbt", utx->psbt);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_txsend(struct command *cmd,
					  const char *buffer,
					  const jsmntok_t *params)
{
	struct unreleased_tx *utx;
	struct out_req *req;

	if (!param(cmd, buffer, params,
		   p_req("txid", param_unreleased_txid, &utx),
		   NULL))
		return command_param_failed();

	/* Remove from list now, to avoid races! */
	list_del_from(&unreleased_txs, &utx->list);
	/* If things go wrong, free it. */
	tal_steal(cmd, utx);

	req = jsonrpc_request_start(cmd->plugin, cmd, "signpsbt",
				    signpsbt_done, forward_error,
				    utx);
	json_add_psbt(req->js, "psbt", utx->psbt);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_withdraw(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *params)
{
	struct txprepare *txp = tal(cmd, struct txprepare);
	struct amount_sat *amount;
	const u8 *scriptpubkey;
	const char *feerate;
	struct bitcoin_outpoint *utxos;
	unsigned int *minconf;

	if (!param(cmd, buffer, params,
		   p_req("destination", param_bitcoin_address,
			 &scriptpubkey),
		   p_req("satoshi", param_sat_or_all, &amount),
		   p_opt("feerate", param_string, &feerate),
		   p_opt_def("minconf", param_number, &minconf, 1),
		   p_opt("utxos", param_outpoint_arr, &utxos),
		   NULL))
		return command_param_failed();

	/* Convert destination/satoshi into array as txprepare expects */
	txp->outputs = tal_arr(txp, struct tx_output, 1);

	if (amount_sat_eq(*amount, AMOUNT_SAT(-1ULL))) {
		txp->all_output_idx = 0;
		txp->output_total = AMOUNT_SAT(0);
	} else {
		txp->all_output_idx = -1;
		txp->output_total = *amount;
	}
	txp->outputs[0].amount = *amount;
	txp->outputs[0].script = scriptpubkey;
	txp->outputs[0].is_to_external = true;
	txp->weight = bitcoin_tx_core_weight(1, tal_count(txp->outputs))
		+ bitcoin_tx_output_weight(tal_bytelen(scriptpubkey));

	txp->is_upgrade = false;
	return txprepare_continue(cmd, txp, feerate, minconf, utxos, true, false);
}

struct listfunds_info {
	struct txprepare *txp;
	const char *feerate;
	bool reservedok;
};

/* Find all the utxos that are p2sh in our wallet */
static struct command_result *listfunds_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct listfunds_info *info)
{
	struct bitcoin_outpoint *utxos;
	const jsmntok_t *outputs_tok, *tok;
	size_t i;
	struct txprepare *txp = info->txp;

	/* Find all the utxos in our wallet that are p2sh! */
	outputs_tok = json_get_member(buf, result, "outputs");
	txp->output_total = AMOUNT_SAT(0);
	if (!outputs_tok)
		plugin_err(cmd->plugin,
			   "`listfunds` payload has no outputs token: %*.s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	utxos = tal_arr(cmd, struct bitcoin_outpoint, 0);
	json_for_each_arr(i, tok, outputs_tok) {
		struct bitcoin_outpoint prev_out;
		struct amount_sat val;
		bool is_reserved;
		char *status;
		const char *err;

		err = json_scan(tmpctx, buf, tok,
				"{amount_msat:%"
				",status:%"
				",reserved:%"
				",txid:%"
				",output:%}",
				JSON_SCAN(json_to_sat, &val),
				JSON_SCAN_TAL(cmd, json_strdup, &status),
				JSON_SCAN(json_to_bool, &is_reserved),
				JSON_SCAN(json_to_txid, &prev_out.txid),
				JSON_SCAN(json_to_number, &prev_out.n));
		if (err)
			plugin_err(cmd->plugin,
				   "`listfunds` payload did not scan. %s: %*.s",
				   err, json_tok_full_len(result),
				   json_tok_full(buf, result));

		/* Skip non-p2sh outputs */
		if (!json_get_member(buf, tok, "redeemscript"))
			continue;

		/* only include confirmed + unconfirmed outputs */
		if (!streq(status, "confirmed")
		    && !streq(status, "unconfirmed"))
			continue;

		if (!info->reservedok && is_reserved)
			continue;

		tal_arr_expand(&utxos, prev_out);
	}

	/* Nothing found to upgrade, return a success */
	if (tal_count(utxos) == 0) {
		struct json_stream *out;
		out = jsonrpc_stream_success(cmd);
		json_add_num(out, "upgraded_outs", tal_count(utxos));
		return command_finished(cmd, out);
	}

	return txprepare_continue(cmd, txp, info->feerate,
				  NULL, utxos, true,
				  info->reservedok);
}

/* We've got an address for sending funds */
static struct command_result *newaddr_sweep_done(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *result,
						 struct listfunds_info *info)
{
	struct out_req *req;
	const jsmntok_t *addr = json_get_member(buf, result, chainparams->is_elements ? "bech32" : "p2tr");
	assert(addr);

	info->txp = tal(info, struct txprepare);
	info->txp->is_upgrade = true;

	/* Add output for 'all' to txp */
	info->txp->outputs = tal_arr(info->txp, struct tx_output, 1);
	info->txp->all_output_idx = 0;
	info->txp->output_total = AMOUNT_SAT(0);
	info->txp->outputs[0].amount = AMOUNT_SAT(-1ULL);
	info->txp->outputs[0].is_to_external = false;

	if (json_to_address_scriptpubkey(info->txp, chainparams, buf, addr,
					 &info->txp->outputs[0].script)
	    != ADDRESS_PARSE_SUCCESS) {
		return command_fail(cmd, LIGHTNINGD,
				    "Change address '%.*s' unparsable?",
				    addr->end - addr->start,
				    buf + addr->start);
	}

	info->txp->weight = bitcoin_tx_core_weight(0, 1)
		+ bitcoin_tx_output_weight(tal_bytelen(info->txp->outputs[0].script));

	/* Find all the utxos we want to spend on this tx */
	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "listfunds",
				    listfunds_done,
				    forward_error,
				    info);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_upgradewallet(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	bool *reservedok;
	struct out_req *req;
	struct listfunds_info *info = tal(cmd, struct listfunds_info);

	if (!param(cmd, buffer, params,
		   p_opt("feerate", param_string, &info->feerate),
		   p_opt_def("reservedok", param_bool, &reservedok, false),
		   NULL))
		return command_param_failed();

	info->reservedok = *reservedok;
	/* Get an address to send everything to */
	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "newaddr",
				    newaddr_sweep_done,
				    forward_error,
				    info);
	json_add_string(req->js, "addresstype", "all");
	return send_outreq(cmd->plugin, req);
}

static const struct plugin_command commands[] = {
	{
		"txprepare",
		"bitcoin",
		"Create a transaction, with option to spend in future (either txsend and txdiscard)",
		"Create an unsigned transaction paying {outputs} with optional {feerate}, {minconf} and {utxos}",
		json_txprepare
	},
	{
		"txdiscard",
		"bitcoin",
		"Discard a transaction created by txprepare",
		"Discard a transcation by {txid}",
		json_txdiscard
	},
	{
		"txsend",
		"bitcoin",
		"Send a transaction created by txprepare",
		"Send a transacation by {txid}",
		json_txsend
	},
	{
		"withdraw",
		"bitcoin",
		"Send funds to {destination} address",
		"Send to {destination} {satoshi} (or 'all') at optional {feerate} using utxos from {minconf} or {utxos}.",
		json_withdraw
	},
	{
		"upgradewallet",
		"bitcoin",
		"Spend p2sh wrapped outputs into a native segwit output",
		"Send all p2sh-wrapped outputs to a bech32 native segwit address",
		json_upgradewallet
	},
};

static void mark_unreleased_txs(struct plugin *plugin, struct htable *memtable)
{
	memleak_scan_list_head(memtable, &unreleased_txs);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	plugin_set_memleak_handler(p, mark_unreleased_txs);
	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL, commands,
		    ARRAY_SIZE(commands), NULL, 0, NULL, 0, NULL, 0, NULL);
}
