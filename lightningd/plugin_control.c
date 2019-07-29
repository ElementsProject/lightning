#include <ccan/tal/path/path.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>
#include <dirent.h>
#include <errno.h>
#include <lightningd/plugin_control.h>
#include <lightningd/plugin_hook.h>
#include <unistd.h>

/**
 * A plugin command which permits to control plugins without restarting
 * lightningd. It takes a subcommand, and an optional subcommand parameter.
 */
static struct command_result *json_plugin_control(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	const char *subcmd;
	subcmd = param_subcommand(cmd, buffer, params,
				  "start", "stop", "startdir", "rescan", "list", NULL);
	if (!subcmd)
		return command_param_failed();

	struct plugin *p;
	struct json_stream *response;

	if (streq(subcmd, "stop")) {
		const char *plugin_name;
		bool plugin_found;

		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   p_req("plugin", param_string, &plugin_name),
			   NULL))
			return command_param_failed();

		plugin_found = false;
		list_for_each(&cmd->ld->plugins->plugins, p, list) {
			if (plugin_paths_match(p->cmd, plugin_name)) {
				if (!p->dynamic)
					return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
							    "%s plugin cannot be managed when lightningd is up",
							    plugin_name);
				plugin_found = true;
				plugin_hook_unregister_all(p);
				plugin_kill(p, "%s stopped by lightningd via RPC",
						plugin_name);
				break;
			}
		}
		if (!plugin_found)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					   "Could not find plugin %s", plugin_name);
	} else if (streq(subcmd, "start")) {
		const char *plugin_path;

		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   p_req("plugin", param_string, &plugin_path),
			   NULL))
			return command_param_failed();

		if (access(plugin_path, X_OK) == 0)
			plugin_register(cmd->ld->plugins, plugin_path);
		else
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						   "%s is not executable: %s",
						   plugin_path, strerror(errno));
	} else if (streq(subcmd, "startdir")) {
		const char *dir_path;

		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   p_req("directory", param_string, &dir_path),
			   NULL))
			return command_param_failed();

		if (access(dir_path, F_OK) == 0)
			add_plugin_dir(cmd->ld->plugins, dir_path, true);
		else
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						   "Could not open %s", dir_path);
	} else if (streq(subcmd, "rescan")) {
		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   NULL))
			return command_param_failed();

		plugins_add_default_dir(cmd->ld->plugins,
				path_join(tmpctx, cmd->ld->config_dir, "plugins"));
	} else if (streq(subcmd, "list")) {
		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   NULL))
			return command_param_failed();
		/* Don't do anything as we return the plugin list anyway */
	}

	/* The config function is called once we got the manifest,
	 * in 'plugin_manifest_cb'.*/
	plugins_start(cmd->ld->plugins, cmd->ld->dev_debug_subprocess);

	response = json_stream_success(cmd);
	json_array_start(response, "plugins");
	list_for_each(&cmd->ld->plugins->plugins, p, list) {
		json_object_start(response, NULL);
		json_add_string(response, "name", p->cmd);
		json_add_bool(response, "active",
			      p->plugin_state == CONFIGURED);
		json_object_end(response);
	}
	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command plugin_control_command = {
	"plugin",
	"plugin",
	json_plugin_control,
	"Control plugins (start, stop, startdir, rescan, list)",
	.verbose = "Usage :\n"
	"plugin start /path/to/a/plugin\n"
	"	adds a new plugin to c-lightning\n"
	"plugin stop plugin_name\n"
	"	stops an already registered plugin\n"
	"plugin startdir /path/to/a/plugin_dir/\n"
	"	adds a new plugin directory\n"
	"plugin rescan\n"
	"	loads not-already-loaded plugins from the default plugins dir\n"
	"plugin list\n"
	"	lists all active plugins\n"
	"\n"
};
AUTODATA(json_command, &plugin_control_command);
