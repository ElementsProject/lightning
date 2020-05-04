#include <ccan/opt/opt.h>
#include <lightningd/options.h>
#include <lightningd/plugin_control.h>
#include <lightningd/plugin_hook.h>
#include <sys/stat.h>
#include <sys/types.h>

/* A dummy structure used to give multiple arguments to callbacks. */
struct dynamic_plugin {
	struct plugin *plugin;
	struct command *cmd;
};

/**
 * Returned by all subcommands on success.
 */
static struct command_result *plugin_dynamic_list_plugins(struct command *cmd)
{
	struct json_stream *response;
	struct plugin *p;

	response = json_stream_success(cmd);
	json_array_start(response, "plugins");
	list_for_each(&cmd->ld->plugins->plugins, p, list) {
		json_object_start(response, NULL);
		json_add_string(response, "name", p->cmd);
		json_add_bool(response, "active",
		              p->plugin_state == INIT_COMPLETE);
		json_object_end(response);
	}
	json_array_end(response);
	return command_success(cmd, response);
}

/* Mutual recursion. */
static void plugin_dynamic_crash(struct plugin *plugin, struct dynamic_plugin *dp);

/**
 * Returned by all subcommands on error.
 */
static struct command_result *
plugin_dynamic_error(struct dynamic_plugin *dp, const char *error)
{
	if (dp->plugin)
		plugin_kill(dp->plugin, "%s", error);
	else
		log_info(dp->cmd->ld->log, "%s", error);

	tal_del_destructor2(dp->plugin, plugin_dynamic_crash, dp);
	return command_fail(dp->cmd, JSONRPC2_INVALID_PARAMS,
	                    "%s: %s", dp->plugin ? dp->plugin->cmd : "unknown plugin",
	                    error);
}

static void plugin_dynamic_timeout(struct dynamic_plugin *dp)
{
	plugin_dynamic_error(dp, "Timed out while waiting for plugin response");
}

static void plugin_dynamic_crash(struct plugin *p, struct dynamic_plugin *dp)
{
	plugin_dynamic_error(dp, "Plugin exited before completing handshake.");
}

static void plugin_dynamic_config_callback(const char *buffer,
                                           const jsmntok_t *toks,
                                           const jsmntok_t *idtok,
                                           struct dynamic_plugin *dp)
{
	struct plugin *p;

	dp->plugin->plugin_state = INIT_COMPLETE;
	/* Reset the timer only now so that we are either configured, or
	 * killed. */
	tal_free(dp->plugin->timeout_timer);
	tal_del_destructor2(dp->plugin, plugin_dynamic_crash, dp);

	list_for_each(&dp->plugin->plugins->plugins, p, list) {
		if (p->plugin_state != INIT_COMPLETE)
			return;
	}

	/* No plugin unconfigured left, return the plugin list */
	was_pending(plugin_dynamic_list_plugins(dp->cmd));
}

/**
 * Send the init message to the plugin. We don't care about its response,
 * but it's considered the last part of the handshake : once it responds
 * it is considered configured.
 */
static void plugin_dynamic_config(struct dynamic_plugin *dp)
{
	struct jsonrpc_request *req;

	req = jsonrpc_request_start(dp->plugin, "init", dp->plugin->log,
	                            plugin_dynamic_config_callback, dp);
	plugin_populate_init_request(dp->plugin, req);
	jsonrpc_request_end(req);
	plugin_request_send(dp->plugin, req);
}

static void plugin_dynamic_manifest_callback(const char *buffer,
                                             const jsmntok_t *toks,
                                             const jsmntok_t *idtok,
                                             struct dynamic_plugin *dp)
{
	if (!plugin_parse_getmanifest_response(buffer, toks, idtok, dp->plugin))
		return was_pending(plugin_dynamic_error(dp, "Gave a bad response to getmanifest"));

	if (!dp->plugin->dynamic)
		return was_pending(plugin_dynamic_error(dp, "Not a dynamic plugin"));

	/* We got the manifest, now send the init message */
	plugin_dynamic_config(dp);
}

/**
 * This starts a plugin : spawns the process, connect its stdout and stdin,
 * then sends it a getmanifest request.
 */
static struct command_result *plugin_start(struct dynamic_plugin *dp)
{
	int stdin, stdout;
	mode_t prev_mask;
	char **p_cmd;
	struct jsonrpc_request *req;
	struct plugin *p = dp->plugin;

	p->dynamic = false;
	p_cmd = tal_arrz(NULL, char *, 2);
	p_cmd[0] = p->cmd;
	/* In case the plugin create files, this is a better default. */
	prev_mask = umask(dp->cmd->ld->initial_umask);
	p->pid = pipecmdarr(&stdin, &stdout, &pipecmd_preserve, p_cmd);
	umask(prev_mask);
	if (p->pid == -1)
		return plugin_dynamic_error(dp, "Error running command");
	else
		log_debug(dp->cmd->ld->plugins->log, "started(%u) %s", p->pid, p->cmd);
	tal_free(p_cmd);
	p->buffer = tal_arr(p, char, 64);
	p->stop = false;
	/* Give the plugin 20 seconds to respond to `getmanifest`, so we don't hang
	 * too long on the RPC caller. */
	p->timeout_timer = new_reltimer(dp->cmd->ld->timers, dp,
	                                time_from_sec((20)),
	                                plugin_dynamic_timeout, dp);

	/* Besides the timeout we could also have the plugin crash before
	 * completing the handshake. In that case we'll get notified and we
	 * can clean up the `struct dynamic_plugin` and return an appropriate
	 * error.
	 *
	 * The destructor is deregistered in the following places:
	 *
	 *  - plugin_dynamic_error in case of a timeout or a crash
	 *  - plugin_dynamic_config_callback if the handshake completes
	 */
	tal_add_destructor2(p, plugin_dynamic_crash, dp);

	/* Create two connections, one read-only on top of the plugin's stdin, and one
	 * write-only on its stdout. */
	io_new_conn(p, stdout, plugin_stdout_conn_init, p);
	io_new_conn(p, stdin, plugin_stdin_conn_init, p);
	req = jsonrpc_request_start(p, "getmanifest", p->log,
	                            plugin_dynamic_manifest_callback, dp);
	jsonrpc_request_end(req);
	plugin_request_send(p, req);
	return command_still_pending(dp->cmd);
}

/**
 * Called when trying to start a plugin through RPC, it starts the plugin and
 * will give a result 20 seconds later at the most.
 */
static struct command_result *
plugin_dynamic_start(struct command *cmd, const char *plugin_path)
{
	struct dynamic_plugin *dp;

	dp = tal(cmd, struct dynamic_plugin);
	dp->cmd = cmd;
	dp->plugin = plugin_register(cmd->ld->plugins, plugin_path);
	if (!dp->plugin)
		return plugin_dynamic_error(dp, "Is already registered");

	return plugin_start(dp);
}

/**
 * Called when trying to start a plugin directory through RPC, it registers
 * all contained plugins recursively and then starts them.
 */
static struct command_result *
plugin_dynamic_startdir(struct command *cmd, const char *dir_path)
{
	const char *err;
	struct plugin *p;
	/* If the directory is empty */
	bool found;

	err = add_plugin_dir(cmd->ld->plugins, dir_path, false);
	if (err)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "%s", err);

	found = false;
	list_for_each(&cmd->ld->plugins->plugins, p, list) {
		if (p->plugin_state == UNCONFIGURED) {
			found = true;
			struct dynamic_plugin *dp = tal(cmd, struct dynamic_plugin);
			dp->plugin = p;
			dp->cmd = cmd;
			plugin_start(dp);
		}
	}
	if (!found)
		plugin_dynamic_list_plugins(cmd);

	return command_still_pending(cmd);
}

static void clear_plugin(struct plugin *p, const char *name)
{
	struct plugin_opt *opt;

	list_for_each(&p->plugin_opts, opt, list)
		if (!opt_unregister(opt->name))
			fatal("Could not unregister %s from plugin %s",
			      opt->name, name);
	plugin_kill(p, "%s stopped by lightningd via RPC", name);
	tal_free(p);
}

static struct command_result *
plugin_dynamic_stop(struct command *cmd, const char *plugin_name)
{
	struct plugin *p;
	struct json_stream *response;

	list_for_each(&cmd->ld->plugins->plugins, p, list) {
		if (plugin_paths_match(p->cmd, plugin_name)) {
			if (!p->dynamic)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				                    "%s cannot be managed when "
				                    "lightningd is up",
				                    plugin_name);
			clear_plugin(p, plugin_name);
			response = json_stream_success(cmd);
			if (deprecated_apis)
				json_add_string(response, "",
			                    take(tal_fmt(NULL, "Successfully stopped %s.",
			                                 plugin_name)));
			json_add_string(response, "result",
			                take(tal_fmt(NULL, "Successfully stopped %s.",
			                             plugin_name)));
			return command_success(cmd, response);
		}
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
	                    "Could not find plugin %s", plugin_name);
}

/**
 * Look for additions in the default plugin directory.
 */
static struct command_result *
plugin_dynamic_rescan_plugins(struct command *cmd)
{
	bool found;
	struct plugin *p;

	/* This will not fail on "already registered" error. */
	plugins_add_default_dir(cmd->ld->plugins);

	found = false;
	list_for_each(&cmd->ld->plugins->plugins, p, list) {
		if (p->plugin_state == UNCONFIGURED) {
			struct dynamic_plugin *dp = tal(cmd, struct dynamic_plugin);
			dp->plugin = p;
			dp->cmd = cmd;
			plugin_start(dp);
			found = true;
		}
	}

	if (!found)
		return plugin_dynamic_list_plugins(cmd);
	return command_still_pending(cmd);
}

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
	                          "start", "stop", "startdir",
	                          "rescan", "list", NULL);
	if (!subcmd)
		return command_param_failed();

	if (streq(subcmd, "stop")) {
		const char *plugin_name;

		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   p_req("plugin", param_string, &plugin_name),
			   NULL))
			return command_param_failed();

		return plugin_dynamic_stop(cmd, plugin_name);
	} else if (streq(subcmd, "start")) {
		const char *plugin_path;

		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   p_req("plugin", param_string, &plugin_path),
			   NULL))
			return command_param_failed();

		if (access(plugin_path, X_OK) == 0)
			return plugin_dynamic_start(cmd, plugin_path);
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
			return plugin_dynamic_startdir(cmd, dir_path);
		else
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						   "Could not open %s", dir_path);
	} else if (streq(subcmd, "rescan")) {
		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   NULL))
			return command_param_failed();

		return plugin_dynamic_rescan_plugins(cmd);
	} else if (streq(subcmd, "list")) {
		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   NULL))
			return command_param_failed();

		return plugin_dynamic_list_plugins(cmd);
	}

	/* subcmd must be one of the above: param_subcommand checked it! */
	abort();
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
