#include <bitcoin/chainparams.c>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/amount.h>
#include <common/features.h>
#include <common/json_stream.h>
#include <common/json_tok.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <plugins/libplugin.h>

const char *placeholder_script = "0020b95810f824f843934fa042acd0becba52087813e260edaeebc42b5cb9abe1464";
const char *placeholder_funding_addr;

/* Populated by libplugin */
extern const struct chainparams *chainparams;

struct funding_req {
	struct node_id *id;
	const char *feerate_str;
	const char *funding_str;
	const char *utxo_str;
	bool funding_all;
	struct amount_msat *push_msat;

	/* Features offered by this peer. */
	const u8 *their_features;

	bool *announce_channel;
	u32 *minconf;

	/* The prepared tx id */
	struct bitcoin_txid tx_id;

	const char *chanstr;
	const u8 *out_script;
	const char *funding_addr;

 	/* Failing result (NULL on success) */
	/* Raw JSON from RPC output */
	const char *error;
};

static struct command_result *send_prior(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *error,
					 struct funding_req *fr)
{
	return command_err_raw(cmd, fr->error);
}

static struct command_result *tx_abort(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *error,
				       struct funding_req *fr)
{
	struct out_req *req;

	/* We stash the error so we can return it after we've cleaned up */
	fr->error = json_strdup(fr, buf, error);

	req = jsonrpc_request_start(cmd->plugin, cmd, "txdiscard",
				    send_prior, send_prior, fr);
	json_add_string(req->js, "txid",
			type_to_string(tmpctx, struct bitcoin_txid, &fr->tx_id));

	/* We need to call txdiscard, and forward the actual cause for the
	 * error after we've cleaned up. We swallow any errors returned by
	 * this call, as we don't really care if it succeeds or not */
	return send_outreq(cmd->plugin, req);
}

/* We're basically done, we just need to format the output to match
 * what the original `fundchannel` returned */
static struct command_result *finish(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *result,
				     struct funding_req *fr)
{
	struct json_stream *out;

	out = jsonrpc_stream_success(cmd);
	json_add_tok(out, "tx", json_get_member(buf, result, "tx"), buf);
	json_add_string(out, "txid",
			type_to_string(tmpctx, struct bitcoin_txid, &fr->tx_id));
	json_add_string(out, "channel_id", fr->chanstr);

	return command_finished(cmd, out);
}

/* We're ready to broadcast the transaction */
static struct command_result *send_tx(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *result,
				      struct funding_req *fr)
{

	struct out_req *req;
	const jsmntok_t *tok;
	bool commitments_secured;

	/* For sanity's sake, let's check that it's secured */
	tok = json_get_member(buf, result, "commitments_secured");
	if (!json_to_bool(buf, tok, &commitments_secured) || !commitments_secured)
		/* TODO: better failure path? this should never fail though. */
		plugin_err(cmd->plugin, "Commitment not secured.");

	/* Stash the channel_id so we can return it when finalized */
	tok = json_get_member(buf, result, "channel_id");
	fr->chanstr = json_strdup(fr, buf, tok);

	req = jsonrpc_request_start(cmd->plugin, cmd, "txsend",
				    finish, tx_abort, fr);
	json_add_string(req->js, "txid",
			type_to_string(tmpctx, struct bitcoin_txid, &fr->tx_id));

	return send_outreq(cmd->plugin, req);
}

static struct command_result *tx_prepare_done(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct funding_req *fr)
{
	const jsmntok_t *txid_tok;
	const jsmntok_t *tx_tok;
	struct out_req *req;
	const struct bitcoin_tx *tx;
	const char *hex;
	u32 outnum;
	bool outnum_found;

	txid_tok = json_get_member(buf, result, "txid");
	if (!txid_tok)
		plugin_err(cmd->plugin, "txprepare missing 'txid' field");

	tx_tok = json_get_member(buf, result, "unsigned_tx");
	if (!tx_tok)
		plugin_err(cmd->plugin, "txprepare missing 'unsigned_tx' field");

	hex = json_strdup(tmpctx, buf, tx_tok);
	tx = bitcoin_tx_from_hex(fr, hex, strlen(hex));
	if (!tx)
		plugin_err(cmd->plugin, "Unable to parse tx %s", hex);

	/* Find the txout */
	outnum_found = false;
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		const u8 *output_script = bitcoin_tx_output_get_script(fr, tx, i);
		if (scripteq(output_script, fr->out_script)) {
			outnum = i;
			outnum_found = true;
			break;
		}
	}
	if (!outnum_found)
		plugin_err(cmd->plugin, "txprepare doesn't include our funding output. "
			   "tx: %s, output: %s",
			   type_to_string(tmpctx, struct bitcoin_tx, tx),
			   tal_hex(tmpctx, fr->out_script));

	hex = json_strdup(tmpctx, buf, txid_tok);
	if (!bitcoin_txid_from_hex(hex, strlen(hex), &fr->tx_id))
		plugin_err(cmd->plugin, "Unable to parse txid %s", hex);

	req = jsonrpc_request_start(cmd->plugin, cmd, "fundchannel_complete",
				    send_tx, tx_abort, fr);
	json_add_string(req->js, "id", node_id_to_hexstr(tmpctx, fr->id));
	/* Note that hex is reused from above */
	json_add_string(req->js, "txid", hex);
	json_add_u32(req->js, "txout", outnum);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *cancel_start(struct command *cmd,
				           const char *buf,
					   const jsmntok_t *error,
					   struct funding_req *fr)
{
	struct out_req *req;

	/* We stash the error so we can return it after we've cleaned up */
	fr->error = json_strdup(fr, buf, error);

	req = jsonrpc_request_start(cmd->plugin, cmd, "fundchannel_cancel",
				    send_prior, send_prior, fr);
	json_add_string(req->js, "id", node_id_to_hexstr(tmpctx, fr->id));

	return send_outreq(cmd->plugin, req);
}

static void txprepare(struct json_stream *js,
		      struct funding_req *fr,
		      const char *destination)
{
	/* Add the 'outputs' */
	json_array_start(js, "outputs");
	json_object_start(js, NULL);
	json_add_string(js, destination, fr->funding_str);
	json_object_end(js);
	json_array_end(js);

	if (fr->feerate_str)
		json_add_string(js, "feerate", fr->feerate_str);
	if (fr->minconf)
		json_add_u32(js, "minconf", *fr->minconf);
	if (fr->utxo_str)
		json_add_jsonstr(js, "utxos", fr->utxo_str);
}

static struct command_result *prepare_actual(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct funding_req *fr)
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd->plugin, cmd, "txprepare",
				    tx_prepare_done, cancel_start,
				    fr);
	txprepare(req->js, fr, fr->funding_addr);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *fundchannel_start_done(struct command *cmd,
						     const char *buf,
						     const jsmntok_t *result,
						     struct funding_req *fr)
{
	struct out_req *req;

	/* Save the outscript so we can fund the outnum later */
	fr->out_script = json_tok_bin_from_hex(fr, buf,
			json_get_member(buf, result, "scriptpubkey"));

	/* Save the funding address, we'll need it later */
	fr->funding_addr = json_strdup(cmd, buf,
				       json_get_member(buf, result, "funding_address"));

	/* Now that we're ready to go, cancel the reserved tx */
	req = jsonrpc_request_start(cmd->plugin, cmd, "txdiscard",
				    prepare_actual, cancel_start,
				    fr);
	json_add_string(req->js, "txid",
			type_to_string(tmpctx, struct bitcoin_txid, &fr->tx_id));

	return send_outreq(cmd->plugin, req);
}

static struct command_result *fundchannel_start(struct command *cmd,
                                                struct funding_req *fr)
{
	struct out_req *req = jsonrpc_request_start(cmd->plugin, cmd,
						    "fundchannel_start",
						    fundchannel_start_done,
						    tx_abort, fr);

	json_add_string(req->js, "id", node_id_to_hexstr(tmpctx, fr->id));

	json_add_string(req->js, "amount", fr->funding_str);

	if (fr->feerate_str)
		json_add_string(req->js, "feerate", fr->feerate_str);
	if (fr->announce_channel)
		json_add_bool(req->js, "announce", *fr->announce_channel);
	if (fr->push_msat)
		json_add_string(req->js, "push_msat",
				type_to_string(tmpctx, struct amount_msat, fr->push_msat));

	return send_outreq(cmd->plugin, req);
}

static struct command_result *post_dryrun(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *result,
					  struct funding_req *fr)
{
	struct bitcoin_tx *tx;
	const char *hex;
	struct amount_sat funding;
	bool funding_found;
	u8 *placeholder = tal_hexdata(tmpctx, placeholder_script, strlen(placeholder_script));
	struct amount_asset asset;

	/* Stash the 'reserved' txid to unreserve later */
	hex = json_strdup(tmpctx, buf, json_get_member(buf, result, "txid"));
	if (!bitcoin_txid_from_hex(hex, strlen(hex), &fr->tx_id))
		plugin_err(cmd->plugin, "Unable to parse reserved txid %s", hex);


	hex = json_strdup(tmpctx, buf, json_get_member(buf, result, "unsigned_tx"));
	tx = bitcoin_tx_from_hex(fr, hex, strlen(hex));
	tx->chainparams = chainparams;

	/* Find the funding amount */
	funding_found = false;
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		const u8 *output_script = bitcoin_tx_output_get_script(tmpctx, tx, i);
		asset = bitcoin_tx_output_get_amount(tx, i);

		/* We do not support funding a channel with anything but the
		 * main asset, for now. */
		if (!amount_asset_is_main(&asset))
			continue;

		if (scripteq(output_script, placeholder)) {
			funding = amount_asset_to_sat(&asset);
			funding_found = true;
			break;
		}
	}

	if (!funding_found)
		plugin_err(cmd->plugin, "Error creating placebo funding tx, funding_out not found. %s", hex);

	/* Update funding to actual amount */
	if (fr->funding_all
	    && !feature_negotiated(plugin_feature_set(cmd->plugin),
				   fr->their_features, OPT_LARGE_CHANNELS)
	    && amount_sat_greater(funding, chainparams->max_funding))
		funding = chainparams->max_funding;

	fr->funding_str = type_to_string(fr, struct amount_sat, &funding);
	return fundchannel_start(cmd, fr);
}

static struct command_result *exec_dryrun(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *result,
					  struct funding_req *fr)
{
	struct out_req *req;
	const jsmntok_t *t;

	/* Stash features so we can wumbo. */
	t = json_get_member(buf, result, "features");
	if (!t)
		plugin_err(cmd->plugin, "No features found in connect response?");
	fr->their_features = json_tok_bin_from_hex(fr, buf, t);
	if (!fr->their_features)
		plugin_err(cmd->plugin, "Bad features '%.*s' in connect response?",
			   t->end - t->start, buf + t->start);

	req = jsonrpc_request_start(cmd->plugin, cmd, "txprepare",
				    post_dryrun, forward_error,
				    fr);

	/* Now that we've tried connecting, we do a 'dry-run' of txprepare,
	 * so we can get an accurate idea of the funding amount */
	txprepare(req->js, fr, placeholder_funding_addr);

	return send_outreq(cmd->plugin, req);

}

static struct command_result *connect_to_peer(struct command *cmd,
                                              struct funding_req *fr)
{
	struct out_req *req = jsonrpc_request_start(cmd->plugin, cmd, "connect",
						    exec_dryrun, forward_error,
						    fr);

	json_add_string(req->js, "id", node_id_to_hexstr(tmpctx, fr->id));

	return send_outreq(cmd->plugin, req);
}

/* We will use 'id' and 'amount' to build a output: {id: amount}.
 * For array type, if we miss 'amount', next parameter will be
 * mistaken for 'amount'.
 * Note the check for 'output' in 'txprepare' is behind of the checks
 * for other parameter, so doing a simply check for 'amount' here can
 * help us locate error correctly.
 */
static struct command_result *param_string_check_sat(struct command *cmd, const char *name,
						     const char * buffer, const jsmntok_t *tok,
						     const char **str)
{
	struct command_result *res;
	struct amount_sat *amount;

	res = param_sat_or_all(cmd, name, buffer, tok, &amount);
	if (res)
		return res;

	return param_string(cmd, name, buffer, tok, str);
}

static struct command_result *json_fundchannel(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct funding_req *fr = tal(cmd, struct funding_req);

	if (!param(cmd, buf, params,
		   p_req("id", param_node_id, &fr->id),
		   p_req("amount", param_string_check_sat, &fr->funding_str),
		   p_opt("feerate", param_string, &fr->feerate_str),
		   p_opt_def("announce", param_bool, &fr->announce_channel, true),
		   p_opt_def("minconf", param_number, &fr->minconf, 1),
		   p_opt("utxos", param_string, &fr->utxo_str),
		   p_opt("push_msat", param_msat, &fr->push_msat),
		   NULL))
		return command_param_failed();

	fr->funding_all = streq(fr->funding_str, "all");

	return connect_to_peer(cmd, fr);
}

static void init(struct plugin *p,
		 const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	/* Figure out what the 'placeholder' addr is */
	const char *network_name;
	u8 *placeholder = tal_hexdata(tmpctx, placeholder_script, strlen(placeholder_script));

	network_name = rpc_delve(tmpctx, p, "listconfigs",
				 take(json_out_obj(NULL, "config",
						   "network")),
				 ".network");
	chainparams = chainparams_for_network(network_name);
	placeholder_funding_addr = encode_scriptpubkey_to_addr(NULL, chainparams,
							       placeholder);
}


static const struct plugin_command commands[] = { {
		"fundchannel",
		"channels",
		"Fund channel with {id} using {amount} (or 'all'), at optional {feerate}. "
		"Only use outputs that have {minconf} confirmations.",
		"Initiaties a channel open with node 'id'. Must "
		"be connected to the node and have enough funds available at the requested minimum confirmation "
		"depth (minconf)",
		json_fundchannel
	}
};


int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL, commands,
		    ARRAY_SIZE(commands), NULL, 0, NULL, 0, NULL);
}
