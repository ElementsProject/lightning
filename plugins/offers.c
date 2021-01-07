/* This plugin covers both sending and receiving offers */
#include <ccan/array_size/array_size.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>
#include <plugins/offers.h>
#include <plugins/offers_inv_hook.h>
#include <plugins/offers_invreq_hook.h>
#include <plugins/offers_offer.h>

struct pubkey32 id;
u32 cltv_final;

static struct command_result *finished(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *result,
				       void *unused)
{
	return command_hook_success(cmd);
}

static struct command_result *sendonionmessage_error(struct command *cmd,
						     const char *buf,
						     const jsmntok_t *err,
						     void *unused)
{
	plugin_log(cmd->plugin, LOG_BROKEN,
		   "sendoniomessage gave JSON error: %.*s",
		   json_tok_full_len(err),
		   json_tok_full(buf, err));
	return command_hook_success(cmd);
}

struct command_result *WARN_UNUSED_RESULT
send_onion_reply(struct command *cmd,
		 const char *jsonbuf,
		 const jsmntok_t *replytok,
		 const char *replyfield,
		 const u8 *replydata)
{
	struct out_req *req;
	size_t i;
	const jsmntok_t *t;

	plugin_log(cmd->plugin, LOG_DBG, "sending reply %s = %s",
		   replyfield, tal_hex(tmpctx, replydata));

	/* Send to requester, using return route. */
	req = jsonrpc_request_start(cmd->plugin, cmd, "sendonionmessage",
				    finished, sendonionmessage_error, NULL);

	/* Add reply into last hop. */
	json_array_start(req->js, "hops");
	json_for_each_arr(i, t, replytok) {
		size_t j;
		const jsmntok_t *t2;

		plugin_log(cmd->plugin, LOG_DBG, "hops[%zu/%i]",
			   i, replytok->size);
		json_object_start(req->js, NULL);
		json_for_each_obj(j, t2, t)
			json_add_tok(req->js,
				     json_strdup(tmpctx, jsonbuf, t2),
				     t2+1, jsonbuf);
		if (i == replytok->size - 1) {
			plugin_log(cmd->plugin, LOG_DBG, "... adding %s",
				   replyfield);
			json_add_hex_talarr(req->js, replyfield, replydata);
		}
		json_object_end(req->js);
	}
	json_array_end(req->js);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *onion_message_call(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const jsmntok_t *om, *invreqtok, *invtok;

	om = json_get_member(buf, params, "onion_message");

	invreqtok = json_get_member(buf, om, "invoice_request");
	if (invreqtok) {
		const jsmntok_t *replytok;

		replytok = json_get_member(buf, om, "reply_path");
		if (replytok && replytok->size > 0)
			return handle_invoice_request(cmd, buf,
						      invreqtok, replytok);
		else
			plugin_log(cmd->plugin, LOG_DBG,
				   "invoice_request without reply_path");
	}

	invtok = json_get_member(buf, om, "invoice");
	if (invtok) {
		const jsmntok_t *replytok;

		replytok = json_get_member(buf, om, "reply_path");
		return handle_invoice(cmd, buf, invtok, replytok);
	}

	return command_hook_success(cmd);
}

static const struct plugin_hook hooks[] = {
	{
		"onion_message",
		onion_message_call
	},
};

static void init(struct plugin *p,
		 const char *buf UNUSED,
		 const jsmntok_t *config UNUSED)
{
	struct pubkey k;

	rpc_scan(p, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_pubkey, &k));
	if (secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &id.pubkey,
					       NULL, &k.pubkey) != 1)
		abort();

	rpc_scan(p, "listconfigs",
		 take(json_out_obj(NULL, "config", "cltv-final")),
		 "{cltv-final:%}", JSON_SCAN(json_to_number, &cltv_final));
}

static const struct plugin_command commands[] = {
    {
	    "offer",
	    "payment",
	    "Create an offer",
            "Create an offer for invoices of {amount} with {destination}, optional {vendor}, {quantity_min}, {quantity_max}, {absolute_expiry}, {recurrence}, {recurrence_base}, {recurrence_paywindow}, {recurrence_limit} and {single_use}",
            json_offer
    },
};

int main(int argc, char *argv[])
{
	setup_locale();

	/* We deal in UTC; mktime() uses local time */
	setenv("TZ", "", 1);
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL, commands,
		    ARRAY_SIZE(commands), NULL, 0, hooks, ARRAY_SIZE(hooks),
		    NULL);
}
