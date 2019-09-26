#include <bitcoin/chainparams.c>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/amount.h>
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

/* Helper to copy JSON object directly into a json_out */
static void json_out_add_raw_len(struct json_out *jout,
				 const char *fieldname,
				 const char *jsonstr, size_t len)
{
	char *p;

	p = json_out_member_direct(jout, fieldname, len);
	memcpy(p, jsonstr, len);
}

/* Helper to add a boolean to a json_out */
static void json_out_addbool(struct json_out *jout,
		             const char *fieldname,
			     const bool val)
{
	if (val)
		json_out_add(jout, fieldname, false, "true");
	else
		json_out_add(jout, fieldname, false, "false");
}

/* Copy field and member to output, if it exists: return member */
static const jsmntok_t *copy_member(struct json_out *ret,
				    const char *buf, const jsmntok_t *obj,
				    const char *membername)
{
	const jsmntok_t *m = json_get_member(buf, obj, membername);
	if (!m)
		return NULL;

	/* Literal copy: it's already JSON escaped, and may be a string. */
	json_out_add_raw_len(ret, membername,
			     json_tok_full(buf, m), json_tok_full_len(m));
	return m;
}

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
	struct json_out *ret;

	/* We stash the error so we can return it after we've cleaned up */
	fr->error = json_strdup(fr, buf, error);

	ret = json_out_new(NULL);
	json_out_start(ret, NULL,  '{');
	json_out_addstr(ret, "txid",
			type_to_string(tmpctx, struct bitcoin_txid, &fr->tx_id));
	json_out_end(ret, '}');

	/* We need to call txdiscard, and forward the actual cause for the
	 * error after we've cleaned up. We swallow any errors returned by
	 * this call, as we don't really care if it succeeds or not */
	return send_outreq(cmd, "txdiscard",
			   send_prior, send_prior,
			   fr, take(ret));
}

/* We're basically done, we just need to format the output to match
 * what the original `fundchannel` returned */
static struct command_result *finish(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *result,
				     struct funding_req *fr)
{
	struct json_out *out;

	out = json_out_new(NULL);
	json_out_start(out, NULL, '{');
	copy_member(out, buf, result, "tx");
	json_out_addstr(out, "txid",
			type_to_string(tmpctx, struct bitcoin_txid, &fr->tx_id));
	json_out_addstr(out, "channel_id", fr->chanstr);
	json_out_end(out, '}');

	return command_success(cmd, out);
}

/* We're ready to broadcast the transaction */
static struct command_result *send_tx(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *result,
				      struct funding_req *fr)
{

	struct json_out *ret;
	const jsmntok_t *tok;
	bool commitments_secured;

	/* For sanity's sake, let's check that it's secured */
	tok = json_get_member(buf, result, "commitments_secured");
	if (!json_to_bool(buf, tok, &commitments_secured) || !commitments_secured)
		/* TODO: better failure path? this should never fail though. */
		plugin_err("Commitment not secured.");

	/* Stash the channel_id so we can return it when finalized */
	tok = json_get_member(buf, result, "channel_id");
	fr->chanstr = json_strdup(fr, buf, tok);

	ret = json_out_new(NULL);
	json_out_start(ret, NULL, '{');
	json_out_addstr(ret, "txid",
			type_to_string(tmpctx, struct bitcoin_txid, &fr->tx_id));
	json_out_end(ret, '}');

	return send_outreq(cmd, "txsend",
			   finish, tx_abort,
			   fr, take(ret));
}

static struct command_result *tx_prepare_done(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct funding_req *fr)
{
	const jsmntok_t *txid_tok;
	const jsmntok_t *tx_tok;
	struct json_out *ret;
	const struct bitcoin_tx *tx;
	const char *hex;
	u32 outnum;
	bool outnum_found;

	txid_tok = json_get_member(buf, result, "txid");
	if (!txid_tok)
		plugin_err("txprepare missing 'txid' field");

	tx_tok = json_get_member(buf, result, "unsigned_tx");
	if (!tx_tok)
		plugin_err("txprepare missing 'unsigned_tx' field");

	hex = json_strdup(tmpctx, buf, tx_tok);
	tx = bitcoin_tx_from_hex(fr, hex, strlen(hex));
	if (!tx)
		plugin_err("Unable to parse tx %s", hex);

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
		plugin_err("txprepare doesn't include our funding output. "
			   "tx: %s, output: %s",
			   type_to_string(tmpctx, struct bitcoin_tx, tx),
			   tal_hex(tmpctx, fr->out_script));

	hex = json_strdup(tmpctx, buf, txid_tok);
	if (!bitcoin_txid_from_hex(hex, strlen(hex), &fr->tx_id))
		plugin_err("Unable to parse txid %s", hex);

	ret = json_out_new(NULL);
	json_out_start(ret, NULL, '{');
	json_out_addstr(ret, "id", node_id_to_hexstr(tmpctx, fr->id));
	/* Note that hex is reused from above */
	json_out_addstr(ret, "txid", hex);
	json_out_add(ret, "txout", false, "%u", outnum);
	json_out_end(ret, '}');

	return send_outreq(cmd, "fundchannel_complete",
			   send_tx, tx_abort,
			   fr, take(ret));
}

static struct command_result *cancel_start(struct command *cmd,
				           const char *buf,
					   const jsmntok_t *error,
					   struct funding_req *fr)
{
	struct json_out *ret;

	/* We stash the error so we can return it after we've cleaned up */
	fr->error = json_strdup(fr, buf, error);

	ret = json_out_new(NULL);
	json_out_start(ret, NULL, '{');
	json_out_addstr(ret, "id", node_id_to_hexstr(tmpctx, fr->id));
	json_out_end(ret, '}');

	return send_outreq(cmd, "fundchannel_cancel",
			   send_prior, send_prior,
			   fr, take(ret));
}

static struct json_out *txprepare(struct command *cmd,
				  struct funding_req *fr,
				  const char *destination)
{
	struct json_out *ret;
	ret = json_out_new(NULL);
	json_out_start(ret, NULL, '{');

	/* Add the 'outputs' */
	json_out_start(ret, "outputs", '[');
	json_out_start(ret, NULL, '{');
	json_out_addstr(ret, destination, fr->funding_str);
	json_out_end(ret, '}');
	json_out_end(ret, ']');

	if (fr->feerate_str)
		json_out_addstr(ret, "feerate", fr->feerate_str);
	if (fr->minconf)
		json_out_add(ret, "minconf", false, "%u", *fr->minconf);
	if (fr->utxo_str)
		json_out_add_raw_len(ret, "utxos", fr->utxo_str, strlen(fr->utxo_str));
	json_out_end(ret, '}');

	return ret;
}

static struct command_result *prepare_actual(struct command *cmd,
						     const char *buf,
						     const jsmntok_t *result,
						     struct funding_req *fr)
{
	struct json_out *ret;

	ret = txprepare(cmd, fr, fr->funding_addr);

	return send_outreq(cmd, "txprepare",
			   tx_prepare_done, cancel_start,
			   fr, take(ret));
}

static struct command_result *fundchannel_start_done(struct command *cmd,
						     const char *buf,
						     const jsmntok_t *result,
						     struct funding_req *fr)
{
	struct json_out *ret;

	/* Save the outscript so we can fund the outnum later */
	fr->out_script = json_tok_bin_from_hex(fr, buf,
			json_get_member(buf, result, "scriptpubkey"));

	/* Save the funding address, we'll need it later */
	fr->funding_addr = json_strdup(cmd, buf,
				       json_get_member(buf, result, "funding_address"));

	/* Now that we're ready to go, cancel the reserved tx */
	ret = json_out_new(NULL);
	json_out_start(ret, NULL,  '{');
	json_out_addstr(ret, "txid",
			type_to_string(tmpctx, struct bitcoin_txid, &fr->tx_id));
	json_out_end(ret, '}');

	return send_outreq(cmd, "txdiscard",
			   prepare_actual, cancel_start,
			   fr, take(ret));
}

static struct command_result *fundchannel_start(struct command *cmd,
						struct funding_req *fr)
{
	struct json_out *ret = json_out_new(NULL);

	json_out_start(ret, NULL, '{');
	json_out_addstr(ret, "id", node_id_to_hexstr(tmpctx, fr->id));
	json_out_addstr(ret, "satoshi", fr->funding_str);

	if (fr->feerate_str)
		json_out_addstr(ret, "feerate", fr->feerate_str);
	if (fr->announce_channel)
		json_out_addbool(ret, "announce", *fr->announce_channel);

	json_out_end(ret, '}');
	json_out_finished(ret);

	/* FIXME: as a nice feature, we should check that the peer
	 * you want to connect to is connected first. if not, we should
	 * connect and then call fundchannel start!  */
	return send_outreq(cmd, "fundchannel_start",
			   fundchannel_start_done, tx_abort,
			   fr, take(ret));
}

static struct command_result *tx_prepare_dryrun(struct command *cmd,
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
		plugin_err("Unable to parse reserved txid %s", hex);


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
		plugin_err("Error creating placebo funding tx, funding_out not found. %s", hex);

	/* Update funding to actual amount */
	if (fr->funding_all && amount_sat_greater(funding, chainparams->max_funding))
		funding = chainparams->max_funding;

	fr->funding_str = type_to_string(fr, struct amount_sat, &funding);
	return fundchannel_start(cmd, fr);
}

static struct command_result *json_fundchannel(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct funding_req *fr = tal(cmd, struct funding_req);
	struct json_out *ret;

	if (!param(cmd, buf, params,
		   p_req("id", param_node_id, &fr->id),
		   p_req("satoshi", param_string, &fr->funding_str),
		   p_opt("feerate", param_string, &fr->feerate_str),
		   p_opt_def("announce", param_bool, &fr->announce_channel, true),
		   p_opt_def("minconf", param_number, &fr->minconf, 1),
		   p_opt("utxos", param_string, &fr->utxo_str),
		   NULL))
		return command_param_failed();

	fr->funding_all = streq(fr->funding_str, "all");

	/* First we do a 'dry-run' of txprepare, so we can get
	 * an accurate idea of the funding amount */
	ret = txprepare(cmd, fr, placeholder_funding_addr);

	return send_outreq(cmd, "txprepare",
			   tx_prepare_dryrun, forward_error,
			   fr, take(ret));

}

static void init(struct plugin_conn *rpc,
		 const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	/* Figure out what the 'placeholder' addr is */
	const char *network_name;
	u8 *placeholder = tal_hexdata(tmpctx, placeholder_script, strlen(placeholder_script));

	network_name = rpc_delve(tmpctx, "listconfigs",
				 take(json_out_obj(NULL, "config",
						   "network")),
			         rpc, ".network");
	chainparams = chainparams_for_network(network_name);
	placeholder_funding_addr = encode_scriptpubkey_to_addr(NULL,
							       chainparams->bip173_name,
							       placeholder);
}


static const struct plugin_command commands[] = { {
		"fundchannel",
		"channels",
		"Fund channel with {id} using {satoshi} (or 'all'), at optional {feerate}. "
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
	plugin_main(argv, init, PLUGIN_RESTARTABLE, commands, ARRAY_SIZE(commands), NULL);
}
