#include <bitcoin/chainparams.h>
#include <bitcoin/feerate.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/json_out/json_out.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/amount.h>
#include <common/features.h>
#include <common/pseudorand.h>
#include <common/json_stream.h>
#include <common/json_tok.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <plugins/libplugin.h>

/* When they specify utxos, we store them here. */
struct txout {
	struct bitcoin_txid txid;
	u32 outnum;

	/* We use listfunds to get these results: */
	struct amount_sat *amount;
	const u8 *scriptpubkey;

	/* This is NULL unless we're p2sh-wrapped */
	const u8 *redeemscript;
};

struct tx_output {
	struct amount_sat amount;
	const u8 *script;
};

struct feerate {
	/* If this is NULL, we need to convert feerate_name */
	u32 *per_kw;
	const char *name;
};

struct txprepare {
	struct tx_output *outputs;
	struct amount_sat output_total;
	/* Weight for core + outputs */
	size_t weight;

	/* Which output is 'all', or -1 (not counted in output_total!) */
	int all_output_idx;

	struct feerate *feerate;

	unsigned int *minconf;

	/* If they gave us UTXOs to spend, we put them here. */
	struct txout *fixed_txos;

	/* Once we have a PSBT, it goes here. */
	struct wally_psbt *psbt;

	/* Once we have reserved all the inputs, this is set. */
	struct amount_sat change_amount;
};


static struct wally_psbt *json_tok_psbt(const tal_t *ctx,
					const char *buffer,
					const jsmntok_t *tok)
{
	return psbt_from_b64(ctx, buffer + tok->start, tok->end - tok->start);
}

struct unreleased_tx {
	struct list_node list;
	struct bitcoin_txid txid;
	struct wally_tx *tx;
	struct wally_psbt *psbt;
};

static LIST_HEAD(unreleased_txs);

static struct command_result *param_txout(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct txout **txouts)
{
	size_t i;
	const jsmntok_t *curr;

	*txouts = tal_arr(cmd, struct txout, tok->size);

	json_for_each_arr(i, curr, tok) {
		jsmntok_t txid_tok, outnum_tok;
		if (!split_tok(buffer, curr, ':', &txid_tok, &outnum_tok))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not decode the outpoint from \"%s\""
					    " The utxos should be specified as"
					    " 'txid:output_index'.",
					    json_strdup(tmpctx, buffer, curr));

		if (!json_to_txid(buffer, &txid_tok, &(*txouts)[i].txid)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not get a txid out of \"%s\"",
					    json_strdup(tmpctx, buffer, &txid_tok));
		}
		if (!json_to_number(buffer, &outnum_tok, &(*txouts)[i].outnum)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Could not get a vout out of \"%s\"",
					    json_strdup(tmpctx, buffer, &outnum_tok));
		}
		/* This is unknown until we do listfunds */
		(*txouts)[i].amount = NULL;
	}

	if (i == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Please specify an array of 'txid:output_index',"
				    " not \"%.*s\"",
				    tok->end - tok->start,
				    buffer + tok->start);
	return NULL;
}

static struct command_result *param_outputs(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    struct txprepare *txp)
{
	size_t i;
	const jsmntok_t *t;

	txp->outputs = tal_arr(txp, struct tx_output, tok->size);
	txp->output_total = AMOUNT_SAT(0);
	txp->all_output_idx = -1;

	/* We assume < 253 inputs, and if we're wrong, the fee
	 * difference is trivial. */
	txp->weight = bitcoin_tx_core_weight(1, tal_count(txp->outputs));

	json_for_each_arr(i, t, tok) {
		enum address_parse_result res;
		struct tx_output *out = &txp->outputs[i];

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

static struct command_result *param_feerate(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    struct feerate **feerate)
{
	*feerate = tal(cmd, struct feerate);

	/* If they give a name, we have to resolve it. */
	if (tok->type == JSMN_STRING && !cisdigit(buffer[tok->start])) {
		(*feerate)->per_kw = NULL;
		(*feerate)->name = json_strdup(*feerate, buffer, tok);
		return NULL;
	}

	return param_feerate_val(cmd, name, buffer, tok, &(*feerate)->per_kw);
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
	psbt_txid(utx->psbt, &txid, &utx->tx);
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

		out = wally_tx_output(txp->outputs[i].script,
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
	}

	utx = tal(NULL, struct unreleased_tx);
	utx->psbt = tal_steal(utx, txp->psbt);
	psbt_txid(txp->psbt, &utx->txid, &utx->tx);
	list_add(&unreleased_txs, &utx->list);

	out = jsonrpc_stream_success(cmd);
	json_add_hex_talarr(out, "unsigned_tx", linearize_wtx(tmpctx, utx->tx));
	json_add_txid(out, "txid", &utx->txid);
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
	/* We need to pay for all outputs, and fees for them. */
	struct amount_sat fee;

	fee = amount_tx_fee(*txp->feerate->per_kw, txp->weight);
	if (!amount_sat_sub(&excess, excess, fee)
	    || !amount_sat_sub(&excess, excess, txp->output_total))
		return false;

	if (!amount_sat_greater_eq(excess, chainparams->dust_limit))
		return false;

	assert(amount_sat_eq(txp->outputs[txp->all_output_idx].amount,
			     AMOUNT_SAT(-1ULL)));
	txp->outputs[txp->all_output_idx].amount = excess;
	return true;
}

/* fundpsbt gets a viable PSBT for us. */
static struct command_result *fundpsbt_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct txprepare *txp)
{
	const jsmntok_t *psbttok;
	struct out_req *req;
	struct amount_sat excess;

	psbttok = json_get_member(buf, result, "psbt");
	txp->psbt = json_tok_psbt(txp, buf, psbttok);
	if (!txp->psbt)
		return command_fail(cmd, LIGHTNINGD,
				    "Unparsable psbt: '%.*s'",
				    psbttok->end - psbttok->start,
				    buf + psbttok->start);

	if (!json_to_sat(buf, json_get_member(buf, result, "excess_msat"),
			 &excess))
		return command_fail(cmd, LIGHTNINGD,
				    "Unparsable excess_msat: '%.*s'",
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
	txp->change_amount = change_amount(excess, *txp->feerate->per_kw);
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

static struct command_result *call_fundpsbt(struct command *cmd,
					    struct txprepare *txp)
{
	struct out_req *req;

	/* Otherwise, we can now try to gather UTXOs. */
	req = jsonrpc_request_start(cmd->plugin, cmd, "fundpsbt",
				    fundpsbt_done, forward_error,
				    txp);

	if (txp->all_output_idx == -1) {
		struct amount_sat fee, reqd;

		/* We need to know the output & core weight, so we can
		 * cover that too. */
		fee = amount_tx_fee(*txp->feerate->per_kw, txp->weight);
		if (!amount_sat_add(&reqd, fee, txp->output_total))
			return command_done_err(cmd,
						JSONRPC2_INVALID_PARAMS,
						"Output overflow adding fee",
						NULL);
		json_add_u64(req->js, "satoshi",
			     reqd.satoshis); /* Raw: JSON arg */
	} else
		json_add_string(req->js, "satoshi", "all");

	json_add_string(req->js, "feerate",
			tal_fmt(tmpctx, "%u%s", *txp->feerate->per_kw,
				feerate_style_name(FEERATE_PER_KSIPA)));

	json_add_u32(req->js, "minconf", *txp->minconf);
	return send_outreq(cmd->plugin, req);
}

static const char *feerate_name(const char *name)
{
	/* We used SLOW, NORMAL, and URGENT as feerate targets previously,
	 * and many commands rely on this syntax now.
	 * It's also really more natural for an user interface. */
	if (streq(name, "slow"))
		return "min_acceptable";
	else if (streq(name, "normal"))
		return "opening";
	else if (streq(name, "urgent"))
		return "unilateral_close";
	return name;
}

/* We've reserved the inputs they told us with 'utxos' */
static struct command_result *reserveinputs_done(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *result,
						 struct txprepare *txp)
{
	struct out_req *req;

	/* Don't need change? */
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

/* P2SH need a scriptsig */
static u8 *scriptsig_for(const tal_t *ctx, const u8 *redeemscript)
{
	u8 *script;

	if (!redeemscript)
		return NULL;

	script = tal_arr(ctx, u8, 0);
	script_push_bytes(&script,
			  redeemscript, tal_bytelen(redeemscript));
	return script;
}

/* getinfo gives us the block height for nLocktime. */
static struct command_result *getinfo_done(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *result,
					   struct txprepare *txp)
{
	const jsmntok_t *blockheight = json_get_member(buf, result, "blockheight");
	u32 locktime;
	struct bitcoin_tx *tx;
	struct out_req *req;

	json_to_number(buf, blockheight, &locktime);

	/* Eventually fuzz it too. */
	if (locktime > 100 && pseudorand(10) == 0)
		locktime -= pseudorand(100);

	/* Now create a PSBT to try to reserve the inputs. */
	tx = bitcoin_tx(cmd, chainparams, 0, 0, locktime);

	for (size_t i = 0; i < tal_count(txp->fixed_txos); i++) {
		bitcoin_tx_add_input(tx, &txp->fixed_txos[i].txid,
				     txp->fixed_txos[i].outnum,
				     BITCOIN_TX_RBF_SEQUENCE,
				     scriptsig_for(tmpctx,
						   txp->fixed_txos[i].redeemscript),
				     *txp->fixed_txos[i].amount,
				     txp->fixed_txos[i].scriptpubkey, NULL);
		if (txp->fixed_txos[i].redeemscript)
			psbt_input_set_redeemscript(tx->psbt, i,
						    txp->fixed_txos[i].redeemscript);
	}

	txp->psbt = tx->psbt;

	/* Now, try reserving the inputs. */
	req = jsonrpc_request_start(cmd->plugin, cmd, "reserveinputs",
				    reserveinputs_done, forward_error,
				    txp);
	json_add_psbt(req->js, "psbt", txp->psbt);

	return send_outreq(cmd->plugin, req);
}

static struct txout *find_txout(const struct txout txouts[],
				const u8 txhash[WALLY_TXHASH_LEN],
				unsigned int outnum)
{
	for (size_t i = 0; i < tal_count(txouts); i++) {
		BUILD_ASSERT(WALLY_TXHASH_LEN == sizeof(txouts[i].txid));
		if (memcmp(&txouts[i].txid, txhash, WALLY_TXHASH_LEN) == 0
		    && txouts[i].outnum == outnum)
			return cast_const(struct txout *, txouts + i);
	}
	return NULL;
}

/* listfunds gives us the amounts we need for the utxos they provided. */
static struct command_result *listfunds_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct txprepare *txp)
{
	size_t i;
	const jsmntok_t *arr, *t;
	struct out_req *req;
	size_t input_weight = 0;
	struct amount_sat in_total, excess, fee;

	in_total = AMOUNT_SAT(0);
	arr = json_get_member(buf, result, "outputs");
	json_for_each_arr(i, t, arr) {
		const jsmntok_t *txidtok, *outputtok, *amounttok, *scripttok, *redeemtok;
		struct bitcoin_txid txid;
		u32 outnum;
		struct amount_sat amount;
		struct txout *txo;

		txidtok = json_get_member(buf, t, "txid");
		outputtok = json_get_member(buf, t, "output");
		amounttok = json_get_member(buf, t, "amount_msat");
		scripttok = json_get_member(buf, t, "scriptpubkey");
		redeemtok = json_get_member(buf, t, "redeemscript");

		if (!json_to_sat(buf, amounttok, &amount)
		    || !json_to_number(buf, outputtok, &outnum)
		    || !json_to_txid(buf, txidtok, &txid))
			plugin_err(cmd->plugin,
				   "listfunds result bad tokens: %.*s",
				   result->end - result->start,
				   buf + result->start);
		txo = find_txout(txp->fixed_txos, txid.shad.sha.u.u8, outnum);
		if (txo) {
			/* Note: txo is not a tal ptr! */
			txo->amount = tal_dup(txp->fixed_txos, struct amount_sat,
					      &amount);
			txo->scriptpubkey = tal_hexdata(txp,
							buf + scripttok->start,
							scripttok->end
							- scripttok->start);
			if (redeemtok) {
				txo->redeemscript = tal_hexdata(txp,
								buf + redeemtok->start,
								redeemtok->end
								- redeemtok->start);
			} else
				txo->redeemscript = NULL;

			input_weight
				+= bitcoin_tx_simple_input_weight(txo->redeemscript != NULL);

			if (!amount_sat_add(&in_total, in_total, amount))
				return command_done_err(cmd,
							LIGHTNINGD,
							"Impossible input amt!",
							NULL);
		}
	}

	/* UTXOs must be known. */
	for (i = 0; i < tal_count(txp->fixed_txos); i++) {
		if (txp->fixed_txos[i].amount)
			continue;

		return command_done_err(cmd,
					JSONRPC2_INVALID_PARAMS,
					tal_fmt(tmpctx,
						"Unknown UTXO %s:%u",
						type_to_string(tmpctx,
							       struct bitcoin_txid,
							       &txp->fixed_txos[i].txid),
						txp->fixed_txos[i].outnum),
					NULL);
	}

	/* Figure out how much we have to pay fee. */
	if (!amount_sat_sub(&excess, in_total, txp->output_total))
		return command_done_err(cmd,
					JSONRPC2_INVALID_PARAMS,
					tal_fmt(tmpctx,
						"Input total %s less than output total %s: maybe try using unconfirmed utxos?",
						type_to_string(tmpctx,
							       struct amount_sat,
							       &in_total),
						type_to_string(tmpctx,
							       struct amount_sat,
							       &txp->output_total)),
					NULL);

	fee = amount_tx_fee(*txp->feerate->per_kw,
			    txp->weight + input_weight);

	if (!amount_sat_sub(&excess, excess, fee))
		return command_done_err(cmd,
					JSONRPC2_INVALID_PARAMS,
					tal_fmt(tmpctx,
						"%s inputs and %s outputs"
						" cannot afford fee %s",
						type_to_string(tmpctx,
							       struct amount_sat,
							       &in_total),
						type_to_string(tmpctx,
							       struct amount_sat,
							       &txp->output_total),
						type_to_string(tmpctx,
							       struct amount_sat,
							       &fee)),
					NULL);

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

	/* Figure if we need change. */
	txp->change_amount = change_amount(excess, *txp->feerate->per_kw);

	/* Now get blockheight, so we can set locktime appropriately. */
	req = jsonrpc_request_start(cmd->plugin, cmd, "getinfo",
				    getinfo_done, forward_error,
				    txp);
	return send_outreq(cmd->plugin, req);
}

/* If they give us a feerate *name*, we use 'feerates' to map it */
static struct command_result *feerates_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct txprepare *txp)
{
	const jsmntok_t *rates, *ratetok;

	if (json_get_member(buf, result, "warning_missing_feerates"))
		return command_fail(cmd, LIGHTNINGD, "Cannot estimate fees");

	rates = json_get_member(buf, result,
				feerate_style_name(FEERATE_PER_KSIPA));
	ratetok = json_get_member(buf, rates, feerate_name(txp->feerate->name));
	if (!ratetok)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Unknown feerate '%s'",
				    txp->feerate->name);
	txp->feerate->per_kw = tal(txp, u32);
	if (!json_to_number(buf, ratetok, txp->feerate->per_kw))
		return command_fail(cmd, LIGHTNINGD,
				    "Unparsable feerate for %s: '%.*s'",
				    txp->feerate->name,
				    ratetok->end - ratetok->start,
				    buf + ratetok->start);

	/* If they specify utxos, we turn them into PSBT directly. */
	if (txp->fixed_txos) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd->plugin, cmd, "listfunds",
					    listfunds_done, forward_error,
					    txp);
		return send_outreq(cmd->plugin, req);
	}

	/* Got feerate, so we're good to go. */
	return call_fundpsbt(cmd, txp);
}

static struct command_result *json_txprepare(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *params)
{
	struct txprepare *txp = tal(cmd, struct txprepare);
	struct out_req *req;

	if (!param(cmd, buffer, params,
		   p_req("outputs", param_outputs, txp),
		   p_opt("feerate", param_feerate, &txp->feerate),
		   p_opt_def("minconf", param_number, &txp->minconf, 1),
		   p_opt("utxos", param_txout, &txp->fixed_txos),
		   NULL))
		return command_param_failed();

	/* Default is opening feerate */
	if (!txp->feerate) {
		txp->feerate = tal(txp, struct feerate);
		txp->feerate->per_kw = NULL;
		txp->feerate->name = "opening";
	}

	/* Do we need to get a feerate? */
	if (!txp->feerate->per_kw) {
		req = jsonrpc_request_start(cmd->plugin, cmd, "feerates",
					    feerates_done, forward_error,
					    txp);
		json_add_string(req->js, "style", feerate_style_name(FEERATE_PER_KSIPA));
		return send_outreq(cmd->plugin, req);
	}

	/* If they specify utxos, we turn them into PSBT directly. */
	if (txp->fixed_txos) {
		req = jsonrpc_request_start(cmd->plugin, cmd, "listfunds",
					    listfunds_done, forward_error,
					    txp);
		return send_outreq(cmd->plugin, req);
	}

	return call_fundpsbt(cmd, txp);
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
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, NULL, PLUGIN_RESTARTABLE, NULL, commands,
		    ARRAY_SIZE(commands), NULL, 0, NULL, 0, NULL);
}
