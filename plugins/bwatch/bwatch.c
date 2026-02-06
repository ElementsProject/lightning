#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/libplugin.h>

static struct plugin *plugin;

static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin = init_cmd->plugin;
	plugin_log(plugin, LOG_INFORM, "bwatch plugin initialized");
	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, NULL, PLUGIN_RESTARTABLE, true, NULL,
		    NULL, 0,  /* commands */
		    NULL, 0,  /* notifications */
		    NULL, 0,  /* hooks */
		    NULL, 0,  /* notification topics */
		    NULL);
}
