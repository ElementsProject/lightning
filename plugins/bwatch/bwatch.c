#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/memleak.h>
#include <plugins/bwatch/bwatch.h>
#include <plugins/bwatch/bwatch_interface.h>
#include <plugins/bwatch/bwatch_scanner.h>
#include <plugins/bwatch/bwatch_store.h>
#include <plugins/bwatch/bwatch_wiregen.h>

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

	bwatch->scriptpubkey_watches = new_htable(bwatch, scriptpubkey_watches);
	bwatch->outpoint_watches = new_htable(bwatch, outpoint_watches);
	bwatch->scid_watches = new_htable(bwatch, scid_watches);
	bwatch->blockdepth_watches = new_htable(bwatch, blockdepth_watches);

	bwatch->block_history = tal_arr(bwatch, struct block_record_wire, 0);

	/* Replay persisted block history.  load_block_history sets
	 * current_height / current_blockhash from the most recent record;
	 * if there are no records, fall back to zero so the first poll
	 * initialises us at the chain tip. */
	bwatch_load_block_history(cmd, bwatch);

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
