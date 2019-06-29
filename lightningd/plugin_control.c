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
 * lightningd. It takes a command as first parameter (named 'control'
 * to avoid ambuiguity), and eventually this control's parameter(s) as
 * optional second and third parameters.
 */
static struct command_result *json_plugin_control(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	const char *control_command, *control_param, *control_second_param;
	struct plugin *p;
	struct json_stream *response;
	bool plugin_found;

	if (!param(cmd, buffer, params,
		   p_req("command", param_string, &control_command),
		   p_opt("parameter", param_string, &control_param),
		   p_opt("second_parameter", param_string, &control_second_param),
		   NULL))
		return command_param_failed();

	if (!control_param && !streq(control_command, "list")
			&& !streq(control_command, "reload"))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					"Missing a required parameter to the"
					" plugin command \"%s\"", control_command);

	if (streq(control_command, "stop")) {
		plugin_found = false;
		list_for_each(&cmd->ld->plugins->plugins, p, list) {
			if (paths_match(p->cmd, control_param)) {
				plugin_found = true;
				plugin_hook_unregister_all(p);
				plugin_kill(p, "%s stopped by lightningd via RPC",
						control_param);
				break;
			}
		}
		if (!plugin_found)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					   "Could not find plugin %s", control_param);
	} else if (streq(control_command, "start")) {
		if (access(control_param, X_OK) == 0)
			plugin_register(cmd->ld->plugins, control_param);
		else
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						   "%s is not executable: %s",
						   control_param, strerror(errno));
	} else if (streq(control_command, "startdir")) {
		if (access(control_param, F_OK) == 0)
			add_plugin_dir(cmd->ld->plugins, control_param, true);
		else
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						   "Could not open %s", control_param);
	} else if (streq(control_command, "reload")) {
		plugins_add_default_dir(cmd->ld->plugins,
				path_join(tmpctx, cmd->ld->config_dir, "plugins"));
	} else if (streq(control_command, "unregister_hook")) {
		plugin_found = false;
		list_for_each(&cmd->ld->plugins->plugins, p, list) {
			if (paths_match(p->cmd, control_param)) {
				plugin_found = true;
				if (plugin_hook_unregister(p, control_second_param))
					break;
				else
					return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
							   "Could not unregister %s for plugin %s",
							   control_param, control_second_param);
			}
		}
		if (!plugin_found)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					   "Could not find plugin %s", control_param);
	} else if (streq(control_command, "list")) {
		/* Don't do anything as we return the plugin list anyway */
	} else {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					"Invalid control : %s should be one of"
					" stop, start, startdir, reload, plugin_reload",
					control_command);
	}

	/* The config function is called once we got the manifest,
	 * in 'plugin_manifest_cb'.*/
	plugins_start(cmd->ld->plugins, cmd->ld->dev_debug_subprocess);

	response = json_stream_success(cmd);
	json_object_start(response, "plugins");
	list_for_each(&cmd->ld->plugins->plugins, p, list)
		json_add_string(response, p->cmd, p->configured ? "active" : "inactive");
	json_object_end(response);

	return command_success(cmd, response);
}

static const struct json_command plugin_control_command = {
	"plugin",
	"plugin",
	json_plugin_control,
	"Control plugins (start, stop, startdir, reload, list)",
	.verbose = "Usage :\n"
	"plugin start /path/to/a/plugin\n"
	"	adds a new plugin to c-lightning\n"
	"plugin stop plugin_name\n"
	"	stops an already registered plugin\n"
	"plugin startdir /path/to/a/plugin_dir/\n"
	"	adds a new plugin directory\n"
	"plugin reload\n"
	"	loads not-already-loaded plugins from the default plugins dir\n"
	"plugin list\n"
	"	lists all active plugins\n"
	"plugin unregister_hook plugin_name hook_name\n"
	"	unregisters the hook for the plugin\n"
	"\n"
};
AUTODATA(json_command, &plugin_control_command);
