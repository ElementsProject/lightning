#include "config.h"
#include <bitcoin/psbt.h>
#include <ccan/array_size/array_size.h>
#include <common/addr.h>
#include <common/json_stream.h>
#include <common/json_tok.h>
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

	/* Once we have reserved all the inputs, this is set. */
	struct amount_sat change_amount;

	/* For withdraw, we actually send immediately. */
	bool is_withdraw;
};

struct unreleased_tx {
	struct list_node list;
	struct bitcoin_txid txid;
	struct wally_tx *tx;
	struct wally_psbt *psbt;
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
				    tal_hex(tmpctx,
					    linearize_wtx(tmpctx,
							  utx->psbt->tx)));
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
	struct json_stream *out;
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
	utx->psbt = tal_steal(utx, txp->psbt);
	psbt_txid(utx, txp->psbt, &utx->txid, &utx->tx);

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
	out = jsonrpc_stream_success(cmd);
	json_add_hex_talarr(out, "unsigned_tx", linearize_wtx(tmpctx, utx->tx));
	json_add_txid(out, "txid", &utx->txid);
	json_add_psbt(out, "psbt", utx->psbt);
	return command_finished(cmd, out);
}

/* newaddr has given us a change address. */
static struct command_result *newaddr_done(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *result,
					   struct txprepare *txp)
{
	size_t num = tal_count(txp->outputs), pos;
	const jsmntok_t *addr = json_get_member(buf, result, "bech32");

	/* Insert change in random position in outputs */
	tal_resize(&txp->outputs, num+1);
	pos = pseudorand(num+1);
	memmove(txp->outputs + pos + 1,
		txp->outputs + pos,
		sizeof(txp->outputs[0]) * (num - pos));

	txp->outputs[pos].amount = txp->change_amount;
	txp->outputs[pos].is_to_external = false;
	if (json_to_address_scriptpubkey(txp, chainparams, buf, addr,
					 &txp->outputs[pos].script)
	    != ADDRESS_PARSE_SUCCESS) {
		return command_fail(cmd, LIGHTNINGD,
				    "Change address '%.*s' unparsable?",
				    addr->end - addr->start,
				    buf + addr->start);
	}

	return finish_txprepare(cmd, txp);
}

static bool resolve_all_output_amount(struct txprepare *txp,
				      struct amount_sat excess)
{
	if (!amount_sat_greater_eq(excess, chainparams->dust_limit))
		return false;

	assert(amount_sat_eq(txp->outputs[txp->all_output_idx].amount,
			     AMOUNT_SAT(-1ULL)));
	txp->outputs[txp->all_output_idx].amount = excess;
	return true;
}

/* fundpsbt/utxopsbt gets a viable PSBT for us. */
static struct command_result *psbt_created(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *result,
					   struct txprepare *txp)
{
	const jsmntok_t *psbttok;
	struct out_req *req;
	struct amount_sat excess;
	u32 weight;

	psbttok = json_get_member(buf, result, "psbt");
	txp->psbt = json_tok_psbt(txp, buf, psbttok);
	if (!txp->psbt)
		return command_fail(cmd, LIGHTNINGD,
				    "Unparsable psbt: '%.*s'",
				    psbttok->end - psbttok->start,
				    buf + psbttok->start);

	if (!json_to_number(buf, json_get_member(buf, result, "feerate_per_kw"),
			    &txp->feerate))
		return command_fail(cmd, LIGHTNINGD,
				    "Unparsable feerate_per_kw: '%.*s'",
				    result->end - result->start,
				    buf + result->start);

	if (!json_to_sat(buf, json_get_member(buf, result, "excess_msat"),
			 &excess))
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

	/* If we have an "all" output, now we can derive its value: excess
	 * in this case will be total value after inputs paid for themselves. */
	if (txp->all_output_idx != -1) {
		if (!resolve_all_output_amount(txp, excess))
			return command_fail(cmd, FUND_CANNOT_AFFORD,
					    "Insufficient funds to make"
					    " 'all' output");

		/* Never produce change if they asked for all */
		excess = AMOUNT_SAT(0);
	}

	/* So, do we need change? */
	txp->change_amount = change_amount(excess, txp->feerate, weight);
	if (amount_sat_eq(txp->change_amount, AMOUNT_SAT(0)))
		return finish_txprepare(cmd, txp);

	/* Ask for a change address */
	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "newaddr",
				    newaddr_done,
				    /* It would be nice to unreserve inputs,
				     * but probably won't happen. */
				    forward_error,
				    txp);
	return send_outreq(cmd->plugin, req);
}

/* Common point for txprepare and withdraw */
static struct command_result *txprepare_continue(struct command *cmd,
						 struct txprepare *txp,
						 const char *feerate,
						 unsigned int *minconf,
						 struct bitcoin_outpoint *utxos,
						 bool is_withdraw)
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
	} else {
		req = jsonrpc_request_start(cmd->plugin, cmd, "fundpsbt",
					    psbt_created, forward_error,
					    txp);
		json_add_u32(req->js, "minconf", *minconf);
	}

	if (txp->all_output_idx == -1)
		json_add_amount_sat_only(req->js, "satoshi", txp->output_total);
	else
		json_add_string(req->js, "satoshi", "all");

	json_add_u32(req->js, "startweight", txp->weight);

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

	return txprepare_continue(cmd, txp, feerate, minconf, utxos, false);
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

	return txprepare_continue(cmd, txp, feerate, minconf, utxos, true);
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
};

#if DEVELOPER
static void mark_unreleased_txs(struct plugin *plugin, struct htable *memtable)
{
	memleak_remove_region(memtable, &unreleased_txs, sizeof(unreleased_txs));
}
#endif

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
#if DEVELOPER
	plugin_set_memleak_handler(p, mark_unreleased_txs);
#endif
	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL, commands,
		    ARRAY_SIZE(commands), NULL, 0, NULL, 0, NULL, 0, NULL);
}
