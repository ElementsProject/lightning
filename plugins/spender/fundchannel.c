#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/spender/fundchannel.h>

static struct command_result *
json_fundchannel(struct command *cmd,
		 const char *buf,
		 const jsmntok_t *params);

const struct plugin_command fundchannel_commands[] = { {
		"fundchannel",
		json_fundchannel
	}
};
const size_t num_fundchannel_commands = ARRAY_SIZE(fundchannel_commands);

static struct command_result *
fundchannel_get_result(struct command *cmd,
		       const char *method,
		       const char *buf,
		       const jsmntok_t *result,
		       void *nothing UNUSED);

/* Generally a bad idea, but makes sense here. */
static struct command_result *param_tok(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t * tok,
					const jsmntok_t **out)
{
	*out = tok;
	return NULL;
}

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
	const jsmntok_t *close_to;
	const jsmntok_t *request_amt;
	const jsmntok_t *compact_lease;
	const jsmntok_t *mindepth;
	const jsmntok_t *reserve;
	const jsmntok_t *channel_type;

	struct out_req *req;

	if (!param(cmd, buf, params,
		   p_req("id", param_string, &id),
		   p_req("amount", param_tok, &amount),
		   p_opt("feerate", param_tok, &feerate),
		   p_opt("announce", param_tok, &announce),
		   p_opt("minconf", param_tok, &minconf),
		   p_opt("utxos", param_tok, &utxos),
		   p_opt("push_msat", param_tok, &push_msat),
		   p_opt("close_to", param_tok, &close_to),
		   p_opt("request_amt", param_tok, &request_amt),
		   p_opt("compact_lease", param_tok, &compact_lease),
		   p_opt("mindepth", param_tok, &mindepth),
		   p_opt("reserve", param_tok, &reserve),
		   p_opt("channel_type", param_tok, &channel_type),
		   NULL))
		return command_param_failed();

	if (request_amt && !compact_lease)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Must pass in 'compact_lease' if requesting"
				    " funds from peer");

	req = jsonrpc_request_start(cmd, "multifundchannel",
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
	if (close_to)
		json_add_tok(req->js, "close_to", close_to, buf);
	if (request_amt) {
		json_add_tok(req->js, "request_amt", request_amt, buf);
		json_add_tok(req->js, "compact_lease", compact_lease, buf);
	}

	if (mindepth)
		json_add_tok(req->js, "mindepth", mindepth, buf);

	if (reserve)
		json_add_tok(req->js, "reserve", reserve, buf);
	if (channel_type)
		json_add_tok(req->js, "channel_type", channel_type, buf);

	json_object_end(req->js);
	json_array_end(req->js);
	if (feerate)
		json_add_tok(req->js, "feerate", feerate, buf);
	if (minconf)
		json_add_tok(req->js, "minconf", minconf, buf);
	if (utxos)
		json_add_tok(req->js, "utxos", utxos, buf);

	return send_outreq(req);
}

static bool json_to_tok(const char *buffer, const jsmntok_t *tok, const jsmntok_t **ret)
{
	*ret = tok;
	return true;
}

static struct command_result *
fundchannel_get_result(struct command *cmd,
		       const char *method,
		       const char *buf,
		       const jsmntok_t *result,
		       void *nothing UNUSED)
{
	const char *err;
	const jsmntok_t *tx;
	const jsmntok_t *txid;
	const jsmntok_t *channel_id;
	const jsmntok_t *outnum;
	const jsmntok_t *close_to_script;
	const jsmntok_t *channel_type;
	struct json_stream *out;

	close_to_script = NULL;
	err = json_scan(cmd, buf, result,
			"{tx:%,"
			"txid:%,"
			"channel_ids:[0:{channel_id:%,outnum:%,channel_type:%,close_to?:%}]}",
			JSON_SCAN(json_to_tok, &tx),
			JSON_SCAN(json_to_tok, &txid),
			JSON_SCAN(json_to_tok, &channel_id),
			JSON_SCAN(json_to_tok, &outnum),
			JSON_SCAN(json_to_tok, &channel_type),
			JSON_SCAN(json_to_tok, &close_to_script));
	if (err) {
		plugin_err(cmd->plugin,
			   "Unexpected result from multifundchannel: %.*s: %s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result), err);
	}

	out = jsonrpc_stream_success(cmd);
	json_add_tok(out, "tx", tx, buf);
	json_add_tok(out, "txid", txid, buf);
	json_add_tok(out, "channel_id", channel_id, buf);
	json_add_tok(out, "channel_type", channel_type, buf);
	json_add_tok(out, "outnum", outnum, buf);
	if (close_to_script)
		json_add_tok(out, "close_to", close_to_script, buf);
	return command_finished(cmd, out);
}
