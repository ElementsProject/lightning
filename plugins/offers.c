/* This plugin covers both sending and receiving offers */
#include <ccan/array_size/array_size.h>
#include <plugins/libplugin.h>
#include <plugins/offers_invreq_hook.h>
#include <plugins/offers_offer.h>

struct pubkey32 id;
u32 cltv_final;

static struct command_result *onion_message_call(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const jsmntok_t *om, *invreqtok;

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
	const char *field;
	struct pubkey k;

	field =
	    rpc_delve(tmpctx, p, "getinfo",
		      take(json_out_obj(NULL, NULL, NULL)),
		      ".id");
	if (!pubkey_from_hexstr(field, strlen(field), &k))
		abort();
	if (secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &id.pubkey,
					       NULL, &k.pubkey) != 1)
		abort();

	field =
	    rpc_delve(tmpctx, p, "listconfigs",
		      take(json_out_obj(NULL, "config", "cltv-final")),
		      ".cltv-final");
	cltv_final = atoi(field);
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
