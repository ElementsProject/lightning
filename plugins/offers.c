/* This plugin covers both sending and receiving offers */
#include <ccan/array_size/array_size.h>
#include <plugins/libplugin.h>
#include <plugins/offers_offer.h>

struct pubkey32 id;

static const struct plugin_hook hooks[] = {
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

	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL, commands,
		    ARRAY_SIZE(commands), NULL, 0, hooks, ARRAY_SIZE(hooks),
		    NULL);
}
