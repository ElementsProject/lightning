#include "config.h"
#include <ccan/json_escape/json_escape.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <errno.h>
#include <lightningd/notification.h>
#include <lightningd/plugin_control.h>
#include <unistd.h>

/* A dummy structure used to give multiple arguments to callbacks. */
struct plugin_command {
	struct command *cmd;
	const char *subcmd;
};

/**
 * Returned by all subcommands on success.
 */
static struct command_result *plugin_dynamic_list_plugins(struct plugin_command *pcmd,
							  const struct plugins *plugins)
{
	struct json_stream *response;
	const struct plugin *p;

	response = json_stream_success(pcmd->cmd);
	json_add_string(response, "command", pcmd->subcmd);
	json_array_start(response, "plugins");
	list_for_each(&plugins->plugins, p, list) {
		json_object_start(response, NULL);
		json_add_string(response, "name", p->cmd);
		json_add_bool(response, "active",
		              p->plugin_state == INIT_COMPLETE);
		json_add_bool(response, "dynamic", p->dynamic);
		json_object_end(response);
	}
	json_array_end(response);
	return command_success(pcmd->cmd, response);
}

struct command_result *plugin_cmd_killed(struct plugin_command *pcmd,
					 struct plugin *plugin, const char *msg)
{
	return command_fail(pcmd->cmd, PLUGIN_ERROR, "%s: %s", plugin->cmd, msg);
}

struct command_result *plugin_cmd_succeeded(struct plugin_command *pcmd,
					    struct plugin *plugin)
{
	return plugin_dynamic_list_plugins(pcmd, plugin->plugins);
}

struct command_result *plugin_cmd_all_complete(struct plugins *plugins,
					       struct plugin_command *pcmd)
{
	return plugin_dynamic_list_plugins(pcmd, plugins);
}

/**
 * Called when trying to start a plugin through RPC, it starts the plugin and
 * will give a result 60 seconds later at the most (once init completes).
 */
static struct command_result *
plugin_dynamic_start(struct plugin_command *pcmd, const char *plugin_path,
		     const char *buffer, const jsmntok_t *params)
{
	struct plugin *p = plugin_register(pcmd->cmd->ld->plugins, plugin_path, pcmd, false, buffer, params);
	const char *err;

	if (!p)
		return command_fail(pcmd->cmd, JSONRPC2_INVALID_PARAMS,
				    "%s: %s", plugin_path,
					    errno ? strerror(errno) : "already registered");

	err = plugin_send_getmanifest(p, pcmd->cmd->id);
	if (err) {
		/* Free plugin with cmd (it owns buffer and params!) */
		tal_steal(pcmd->cmd, p);
		return command_fail(pcmd->cmd, PLUGIN_ERROR,
				    "%s: %s",
				    plugin_path, err);
	}

	/* This will come back via plugin_cmd_killed or plugin_cmd_succeeded */
	return command_still_pending(pcmd->cmd);
}

/* Returns true if params is an object with keys other than the fixed
 * subcommand/plugin/options. */
static bool plugin_has_extra_params(const char *buffer,
				    const jsmntok_t *params)
{
	size_t i;
	const jsmntok_t *t;

	json_for_each_obj(i, t, params)
		if (!json_tok_streq(buffer, t, "subcommand")
		    && !json_tok_streq(buffer, t, "plugin")
		    && !json_tok_streq(buffer, t, "options"))
			return true;
	return false;
}

/* Build an object of name/value pairs from an "options" array of
 * "keyword=value" strings, suitable for plugin_add_params().  An element
 * without an '=' is treated as a boolean flag. */
static jsmntok_t *plugin_start_params(const tal_t *ctx, const char *buffer,
				      const jsmntok_t *options, char **parambuf)
{
	size_t i;
	const jsmntok_t *t;
	char *newbuf = tal_strdup(ctx, "{");
	bool first = true;

	json_for_each_arr(i, t, options) {
		const char *opt = json_strdup(tmpctx, buffer, t);
		const char *eq = strchr(opt, '=');
		struct json_escape *esc;

		if (!first)
			tal_append_fmt(&newbuf, ",");
		first = false;
		if (eq) {
			esc = json_escape(tmpctx,
					  take(tal_strndup(tmpctx, opt, eq - opt)));
			tal_append_fmt(&newbuf, "\"%s\":", esc->s);
			esc = json_escape(tmpctx, eq + 1);
			tal_append_fmt(&newbuf, "\"%s\"", esc->s);
		} else {
			/* Boolean flags are given without a value. */
			esc = json_escape(tmpctx, opt);
			tal_append_fmt(&newbuf, "\"%s\":true", esc->s);
		}
	}

	tal_append_fmt(&newbuf, "}");
	*parambuf = newbuf;
	return json_parse_simple(ctx, newbuf, strlen(newbuf));
}

/**
 * Called when trying to start a plugin directory through RPC, it registers
 * all contained plugins recursively and then starts them.
 */
static struct command_result *
plugin_dynamic_startdir(struct plugin_command *pcmd, const char *dir_path)
{
	const char *err;
	struct command_result *res;

	err = add_plugin_dir(pcmd->cmd->ld->plugins, dir_path, false);
	if (err)
		return command_fail(pcmd->cmd, JSONRPC2_INVALID_PARAMS, "%s", err);

	/* If none added, this calls plugin_cmd_all_complete immediately */
	res = plugin_register_all_complete(pcmd->cmd->ld, pcmd);
	if (res)
		return res;

	plugins_send_getmanifest(pcmd->cmd->ld->plugins, pcmd->cmd->id);
	return command_still_pending(pcmd->cmd);
}

static struct command_result *plugin_stop(struct command *cmd, struct plugin *p,
					  bool kill)
{
	struct json_stream *response;
	const char *stopmsg = tal_fmt(NULL, "Successfully stopped %s.",
				      p->shortname);

	if (kill)
		plugin_kill(p, LOG_INFORM, "stopped by lightningd via RPC");

	response = json_stream_success(cmd);
	json_add_string(response, "command", "stop");
	json_add_string(response, "result", take(stopmsg));
	return command_success(cmd, response);
}

/* If plugin stops itself, we end up here. */
static void plugin_stopped(struct plugin *p, struct command *cmd)
{
	plugin_stop(cmd, p, false);
}

struct plugin_stop_timeout {
	struct command *cmd;
	struct plugin *p;
};

static void plugin_stop_timeout(struct plugin_stop_timeout *pst)
{
	log_unusual(pst->p->log, "Timeout on shutdown: killing anyway");
	tal_del_destructor2(pst->p, plugin_stopped, pst->cmd);
	plugin_stop(pst->cmd, pst->p, true);
}

static struct command_result *
plugin_dynamic_stop(struct command *cmd, const char *plugin_name)
{
	struct plugin *p;

	list_for_each(&cmd->ld->plugins->plugins, p, list) {
		if (plugin_paths_match(p->cmd, plugin_name)) {
			if (!p->dynamic)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				                    "%s cannot be managed when "
				                    "lightningd is up",
				                    plugin_name);
			/* Don't freak out, even if it's a built-in */
			p->important = false;

			/* If it's interested in clean shutdown, tell it. */
			if (notify_plugin_shutdown(cmd->ld, p)) {
				struct plugin_stop_timeout *pst;

				/* Kill in 30 seconds if it doesn't exit. */
				pst = tal(p, struct plugin_stop_timeout);
				pst->p = p;
				pst->cmd = cmd;
				notleak(new_reltimer(cmd->ld->timers, pst,
						     time_from_sec(30),
						     plugin_stop_timeout,
						     pst));

				tal_add_destructor2(p, plugin_stopped, cmd);
				return command_still_pending(cmd);
			}
			return plugin_stop(cmd, p, true);
		}
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
	                    "Could not find plugin %s", plugin_name);
}

/**
 * Look for additions in the default plugin directory.
 */
static struct command_result *
plugin_dynamic_rescan_plugins(struct plugin_command *pcmd)
{
	struct command_result *res;

	/* This will not fail on "already registered" error. */
	plugins_add_default_dir(pcmd->cmd->ld->plugins);

	/* If none added, this calls plugin_cmd_all_complete immediately */
	res = plugin_register_all_complete(pcmd->cmd->ld, pcmd);
	if (res)
		return res;

	plugins_send_getmanifest(pcmd->cmd->ld->plugins, pcmd->cmd->id);
	return command_still_pending(pcmd->cmd);
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
	struct plugin_command *pcmd;
	const char *subcmd;
	subcmd = param_subcommand(cmd, buffer, params,
	                          "start", "stop", "startdir",
	                          "rescan", "list", NULL);
	if (!subcmd)
		return command_param_failed();

	pcmd = tal(cmd, struct plugin_command);
	pcmd->cmd = cmd;
	pcmd->subcmd = subcmd;

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
		const jsmntok_t *options = NULL;
		char *mod_buffer;
		jsmntok_t *mod_params;

		if (!param_check(cmd, buffer, params,
				 p_req("subcommand", param_ignore, cmd),
				 p_req("plugin", param_string, &plugin_path),
				 p_opt("options", param_array, &options),
				 p_opt_any(),
				 NULL))
			return command_param_failed();

		/* The "options" array is documented as containing keyword=value
		 * strings: reject anything else before we mangle it. */
		if (options) {
			size_t i;
			const jsmntok_t *t;

			json_for_each_arr(i, t, options)
				if (t->type != JSMN_STRING)
					return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
							    "options array entries must be strings");
		}

		/* Manually parse any remaining options (only for objects,
		 * since plugin options must be explicitly named!). */
		if (params->type == JSMN_ARRAY) {
			if (params->size > (options ? 3 : 2))
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Extra parameters must be in object");
			if (options) {
				mod_params = plugin_start_params(cmd, buffer,
								options, &mod_buffer);
			} else {
				mod_buffer = NULL;
				mod_params = NULL;
			}
		} else if (options) {
			/* Either flattened keyword options or an explicit
			 * "options" array, never both. */
			if (plugin_has_extra_params(buffer, params))
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Cannot mix 'options' array "
						    "with keyword options");
			mod_params = plugin_start_params(cmd, buffer,
							options, &mod_buffer);
		} else {
			mod_buffer = NULL;
			mod_params = json_tok_copy(cmd, params);

			json_tok_remove(&mod_params, mod_params,
					json_get_member(buffer, mod_params,
							"subcommand") - 1, 1);
			json_tok_remove(&mod_params, mod_params,
					json_get_member(buffer, mod_params,
							"plugin") - 1, 1);
		}
		if (access(plugin_path, X_OK) != 0)
			plugin_path = path_join(cmd,
					cmd->ld->plugins->default_dir, plugin_path);
		if (access(plugin_path, X_OK) != 0)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						   "%s is not executable: %s",
						   plugin_path, strerror(errno));
		if (command_check_only(cmd))
			return command_check_done(cmd);

		return plugin_dynamic_start(pcmd, plugin_path,
					    mod_buffer ? mod_buffer : buffer,
					    mod_params);
	} else if (streq(subcmd, "startdir")) {
		const char *dir_path;

		if (!param_check(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   p_req("directory", param_string, &dir_path),
			   NULL))
			return command_param_failed();

		if (access(dir_path, F_OK) != 0)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						   "Could not open %s", dir_path);
		if (command_check_only(cmd))
			return command_check_done(cmd);
		return plugin_dynamic_startdir(pcmd, dir_path);
	} else if (streq(subcmd, "rescan")) {
		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   NULL))
			return command_param_failed();

		return plugin_dynamic_rescan_plugins(pcmd);
	} else if (streq(subcmd, "list")) {
		if (!param(cmd, buffer, params,
			   p_req("subcommand", param_ignore, cmd),
			   NULL))
			return command_param_failed();

		return plugin_dynamic_list_plugins(pcmd, cmd->ld->plugins);
	}

	/* subcmd must be one of the above: param_subcommand checked it! */
	abort();
}

static const struct json_command plugin_control_command = {
	"plugin",
	json_plugin_control,
};
AUTODATA(json_command, &plugin_control_command);
