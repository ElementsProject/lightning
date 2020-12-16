/* This plugin covers both sending and receiving offers */
#include <bitcoin/chainparams.h>
#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/json_stream.h>
#include <common/overflows.h>
#include <common/type_to_string.h>
#include <plugins/libplugin.h>
#include <wire/onion_wire.h>

static const struct plugin_hook hooks[] = {
};

static void init(struct plugin *p,
		 const char *buf UNUSED,
		 const jsmntok_t *config UNUSED)
{
}

static const struct plugin_command commands[] = {
};

int main(int argc, char *argv[])
{
	setup_locale();

	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL, commands,
		    ARRAY_SIZE(commands), NULL, 0, hooks, ARRAY_SIZE(hooks),
		    NULL);
}
