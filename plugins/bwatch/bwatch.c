#include "config.h"
#include <ccan/array_size/array_size.h>
#include <plugins/bwatch/bwatch.h>
#include <plugins/bwatch/bwatch_interface.h>
#include <plugins/bwatch/bwatch_scanner.h>
#include <plugins/bwatch/bwatch_store.h>

struct bwatch *bwatch_of(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct bwatch);
}

static const char *init(struct command *cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);

	bwatch->plugin = cmd->plugin;
	return NULL;
}

static const struct plugin_command commands[] = {
	/* Subsequent commits register addwatch / delwatch / listwatch here. */
};

int main(int argc, char *argv[])
{
	struct bwatch *bwatch;

	setup_locale();
	bwatch = tal(NULL, struct bwatch);
	bwatch->poll_interval_ms = 30000;

	plugin_main(argv, init, take(bwatch), PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    NULL, 0,
		    NULL, 0,
		    NULL, 0,
		    plugin_option("bwatch-poll-interval", "int",
				  "Milliseconds between chain polls (default: 30000)",
				  u32_option, u32_jsonfmt, &bwatch->poll_interval_ms),
		    NULL);
}
