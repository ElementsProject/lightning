#ifndef LIGHTNING_LIGHTNINGD_PLUGIN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_PLUGIN_CONTROL_H
#include "config.h"
#include <lightningd/plugin.h>

struct plugin_command;

/* Plugin startup failed */
struct command_result *plugin_cmd_killed(struct plugin_command *pcmd,
					 struct plugin *plugin, const char *msg);

/* Plugin startup succeeded */
struct command_result *plugin_cmd_succeeded(struct plugin_command *pcmd,
					    struct plugin *plugin);

/* All plugins succeeded/failed */
struct command_result *plugin_cmd_all_complete(struct plugins *plugins,
					       struct plugin_command *pcmd);

#endif /* LIGHTNING_LIGHTNINGD_PLUGIN_CONTROL_H */
