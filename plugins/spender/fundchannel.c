#include <ccan/array_size/array_size.h>
#include <ccan/compiler/compiler.h>
#include <common/json.h>
#include <common/json_stream.h>
#include <plugins/spender/fundchannel.h>

static struct command_result *
json_fundchannel(struct command *cmd,
		 const char *buf,
		 const jsmntok_t *params);

const struct plugin_command fundchannel_commands[] = { {
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
const size_t num_fundchannel_commands = ARRAY_SIZE(fundchannel_commands);

static struct command_result *
fundchannel_get_result(struct command *cmd,
		       const char *buf,
		       const jsmntok_t *result,
		       void *nothing UNUSED);

/* Thin wrapper aroud multifundchannel.  */
static struct command_result *
json_fundchannel(struct command *cmd,
		 const char *buf,
		 const jsmntok_t *params)
{
	const char *id;
	const jsmntok_t *amount;
	const jsmntok_t *feerate;
	const jsmntok_t *announce;
	const jsmntok_t *minconf;
	const jsmntok_t *utxos;
	const jsmntok_t *push_msat;

	struct out_req *req;

	if (!param(cmd, buf, params,
		   p_req("id", param_string, &id),
		   p_req("amount", param_tok, &amount),
		   p_opt("feerate", param_tok, &feerate),
		   p_opt("announce", param_tok, &announce),
		   p_opt("minconf", param_tok, &minconf),
		   p_opt("utxos", param_tok, &utxos),
		   p_opt("push_msat", param_tok, &push_msat),
		   NULL))
		return command_param_failed();

	req = jsonrpc_request_start(cmd->plugin, cmd, "multifundchannel",
				    &fundchannel_get_result, &forward_error,
				    NULL);

	json_array_start(req->js, "destinations");
	json_object_start(req->js, NULL);
	json_add_string(req->js, "id", id);
	json_add_tok(req->js, "amount", amount, buf);
	if (announce)
		json_add_tok(req->js, "announce", announce, buf);
	if (push_msat)
		json_add_tok(req->js, "push_msat", push_msat, buf);
	json_object_end(req->js);
	json_array_end(req->js);
	if (feerate)
		json_add_tok(req->js, "feerate", feerate, buf);
	if (minconf)
		json_add_tok(req->js, "minconf", minconf, buf);
	if (utxos)
		json_add_tok(req->js, "utxos", utxos, buf);

	return send_outreq(cmd->plugin, req);
}

static struct command_result *
fundchannel_get_result(struct command *cmd,
		       const char *buf,
		       const jsmntok_t *result,
		       void *nothing UNUSED)
{
	bool ok;
	const jsmntok_t *tx;
	const jsmntok_t *txid;
	const jsmntok_t *channel_ids_array;
	const jsmntok_t *channel_ids_obj;
	const jsmntok_t *channel_id;
	const jsmntok_t *outnum;

	struct json_stream *out;

	ok = true;
	tx = ok ? json_get_member(buf, result, "tx") : NULL;
	ok = ok && tx;
	txid = ok ? json_get_member(buf, result, "txid") : NULL;
	ok = ok && txid;
	channel_ids_array = ok ? json_get_member(buf, result, "channel_ids") : NULL;
	ok = ok && channel_ids_array;
	channel_ids_obj = ok ? json_get_arr(channel_ids_array, 0) : NULL;
	ok = ok && channel_ids_obj;
	channel_id = ok ? json_get_member(buf, channel_ids_obj, "channel_id") : NULL;
	ok = ok && channel_id;
	outnum = ok ? json_get_member(buf, channel_ids_obj, "outnum") : NULL;
	ok = ok && outnum;

	if (!ok)
		plugin_err(cmd->plugin,
			   "Unexpected result from nultifundchannel: %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	out = jsonrpc_stream_success(cmd);
	json_add_tok(out, "tx", tx, buf);
	json_add_tok(out, "txid", txid, buf);
	json_add_tok(out, "channel_id", channel_id, buf);
	json_add_tok(out, "outnum", outnum, buf);
	return command_finished(cmd, out);
}
