#ifndef LIGHTNING_LIGHTNINGD_PLUGIN_H
#define LIGHTNING_LIGHTNINGD_PLUGIN_H
#include "config.h"
#include <ccan/intmap/intmap.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>


enum plugin_state {
	/* We have to ask getmanifest */
	UNCONFIGURED,
	/* We sent getmanifest, need response. */
	AWAITING_GETMANIFEST_RESPONSE,
	/* Got `getmanifest` reply, now we need to send `init`. */
	NEEDS_INIT,
	/* We have to get `init` response */
	AWAITING_INIT_RESPONSE,
	/* We have `init` response. */
	INIT_COMPLETE
};

/**
 * A plugin, exposed as a stub so we can pass it as an argument.
 */
struct plugin {
	/* Must be first element in the struct otherwise we get false
	 * positives for leaks. */
	struct list_node list;

	/* The filename that can be used to refer to the plugin. */
	const char *shortname;

	pid_t pid;
	char *cmd;
	u32 checksum;
	struct io_conn *stdin_conn, *stdout_conn;
	struct plugins *plugins;
	const char **plugin_path;

	/* If there's a json command which ordered this to start */
	struct plugin_command *start_cmd;

	enum plugin_state plugin_state;

	/* Our unique index, which is default hook ordering. */
	u64 index;

	/* If this plugin can be restarted without restarting lightningd */
	bool dynamic;

	/* Stuff we read */
	char *buffer;
	size_t used, len_read;
	jsmn_parser parser;
	jsmntok_t *toks;

	/* Our json_streams. Since multiple streams could start
	 * returning data at once, we always service these in order,
	 * freeing once empty. */
	struct json_stream **js_arr;

	struct logger *log;

	/* List of options that this plugin registered */
	struct list_head plugin_opts;

	const char **methods;

	/* Timer to add a timeout to some plugin RPC calls. Used to
	 * guarantee that `getmanifest` doesn't block indefinitely. */
	const struct oneshot *timeout_timer;

	/* An array of subscribed topics */
	char **subscriptions;

	/* Currently pending requests by their request ID */
	STRMAP(struct jsonrpc_request *) pending_requests;

	/* An array of currently pending RPC method calls, to be killed if the
	 * plugin exits. */
	struct list_head pending_rpccalls;

	/* If set, the plugin is so important that if it terminates early,
	 * C-lightning should terminate as well.  */
	bool important;

	/* Can this handle non-numeric JSON ids? */
	bool non_numeric_ids;

	/* Parameters for dynamically-started plugins. */
	const char *parambuf;
	const jsmntok_t *params;

	/* Notification topics that this plugin has registered with us
	 * and that other plugins may subscribe to. */
	const char **notification_topics;

	/* Custom message types we want to allow incoming */
	u16 *custom_msgs;
};

/**
 * A collection of plugins, and some associated information.
 *
 * Mainly used as root context for calls in the plugin subsystem.
 */
struct plugins {
	struct list_head plugins;
	bool startup;

	/* Normally we want to wrap callbacks in a db transaction, but
	 * not for the db hook servicing */
	bool want_db_transaction;

	struct logger *log;

	struct lightningd *ld;
	const char *default_dir;

	/* If there are json commands waiting for plugin resolutions. */
	struct plugin_command **plugin_cmds;

	/* Blacklist of plugins from --disable-plugin */
	const char **blacklist;

	/* Index to show what order they were added in */
	u64 plugin_idx;

	/* Whether builtin plugins should be overridden as unimportant.  */
	bool dev_builtin_plugins_unimportant;
};

/**
 * Simple storage for plugin options inbetween registering them on the
 * command line and passing them off to the plugin
 */
struct plugin_opt {
	struct plugin *plugin;
	/* off plugin->plugin_opts */
	struct list_node list;
	/* includes -- prefix! */
	const char *name;
	const char *description;
	/* NULL if no default */
	const char *def;
	bool deprecated;
};

/**
 * Create a new plugins context.
 */
struct plugins *plugins_new(const tal_t *ctx, struct log_book *log_book,
			    struct lightningd *ld);

/**
 * Recursively add all plugins from the default plugins directory.
 */
void plugins_add_default_dir(struct plugins *plugins);

/**
 * Initialize the registered plugins.
 *
 * Initialization includes spinning up the plugins, reading their
 * manifest, and registering the JSON-RPC passthrough and command line
 * arguments. In order to read the getmanifest reply from the plugins
 * we spin up our own io_loop that exits once all plugins have
 * responded.
 */
void plugins_init(struct plugins *plugins);

/**
 * Register a plugin for initialization and execution.
 *
 * @param plugins: Plugin context
 * @param path: The path of the executable for this plugin
 * @param start_cmd: The optional JSON command which caused this.
 * @param important: The plugin is important.
 * @param parambuf: NULL, or the JSON buffer for extra parameters.
 * @param params: NULL, or the tokens for extra parameters.
 *
 * If @start_cmd, then plugin_cmd_killed or plugin_cmd_succeeded will be called
 * on it eventually.
 */
struct plugin *plugin_register(struct plugins *plugins,
			       const char* path TAKES,
			       struct plugin_command *start_cmd,
			       bool important,
			       const char *parambuf STEALS,
			       const jsmntok_t *params STEALS);


/**
 * Returns true if the provided name matches a plugin command
 */
bool plugin_paths_match(const char *cmd, const char *name);

/**
 * Remove a plugin registered for initialization.
 *
 * @param plugins: Plugin context
 * @param arg: The basename or fullname of the executable for this plugin
 */
void plugin_blacklist(struct plugins *plugins, const char *name);

/**
 * Is a plugin disabled?.
 *
 * @param plugins: Plugin context
 * @param arg: The basename or fullname of the executable for this plugin
 */
bool plugin_blacklisted(struct plugins *plugins, const char *name);

/**
 * Kick off initialization of a plugin.
 * @p: plugin
 * @cmd_id: optional JSON cmd_id which caused this.
 *
 * Returns error string, or NULL.
 */
const char *plugin_send_getmanifest(struct plugin *p, const char *cmd_id);

/**
 * Kick of initialization of all plugins which need it/
 *
 * Return true if any were started.
 */
bool plugins_send_getmanifest(struct plugins *plugins, const char *cmd_id);

/**
 * Kill a plugin process and free @plugin, with an error message.
 */
void plugin_kill(struct plugin *plugin, enum log_level loglevel,
		 const char *fmt, ...);

/**
 * Tell all the plugins we're shutting down, and free them.
 */
void shutdown_plugins(struct lightningd *ld);

/**
 * Returns the plugin which registers the command with name {cmd_name}
 */
struct plugin *find_plugin_for_command(struct lightningd *ld,
				       const char *cmd_name);


/**
 * Call plugin_cmd_all_complete once all plugins are init or killed.
 *
 * Returns NULL if it's still pending. otherwise, returns
 * plugin_cmd_all_complete().
 */
struct command_result *plugin_register_all_complete(struct lightningd *ld,
						    struct plugin_command *pcmd);

/**
 * Send the configure message to all plugins.
 *
 * Once we've collected all the command line arguments we can go ahead
 * and send them over to the plugin. This finalizes the initialization
 * of the plugins and signals that lightningd is now ready to process
 * incoming JSON-RPC calls and messages.
 *
 * It waits for plugins to be initialized, but returns false if we
 * should exit (an important plugin failed, or we got a shutdown command).
 */
bool plugins_config(struct plugins *plugins);

/**
 * This populates the jsonrpc request with the plugin/lightningd specifications
 */
void plugin_populate_init_request(struct plugin *p, struct jsonrpc_request *req);

/**
 * Add the plugin option and their respective options to listconfigs.
 *
 * This adds a dict that maps the plugin name to a dict of configuration options
 * for the corresponding plugins.
 */
void json_add_opt_plugins(struct json_stream *response,
			  const struct plugins *plugins);


/**
 * Add the disable-plugins options to listconfigs.
 */
void json_add_opt_disable_plugins(struct json_stream *response,
				  const struct plugins *plugins);

/**
 * Used by db hooks which can't have any other I/O while talking to
 * hooked plugins.
 *
 * @param plugins - a `tal`-allocated array of plugins that are the
 * only ones we talk to.
 *
 * @return output of io_loop() (ie. whatever gets passed to io_break()
 * to end exclusive loop).
 */
void *plugins_exclusive_loop(struct plugin **plugins);

/**
 * Add a directory to the plugin path to automatically load plugins.
 */
char *add_plugin_dir(struct plugins *plugins, const char *dir,
		     bool error_ok);

/**
 * Clear all plugins registered so far.
 */
void clear_plugins(struct plugins *plugins);

/**
 * Send notification to this single plugin, if interested.
 *
 * Returns true if it was subscribed to the notification.
 */
bool plugin_single_notify(struct plugin *p,
			  const struct jsonrpc_notification *n TAKES);

/**
 * Send notification to all interested plugins.
 */
void plugins_notify(struct plugins *plugins,
		    const struct jsonrpc_notification *n TAKES);

/**
 * Send a jsonrpc_request to the specified plugin
 */
void plugin_request_send(struct plugin *plugin,
			 struct jsonrpc_request *req TAKES);

/**
 * Callback called when parsing options. It just stores the value in
 * the plugin_opt
 */
char *plugin_opt_set(const char *arg, struct plugin_opt *popt);

/**
 * Callback called when plugin flag-type options.It just stores
 * the value in the plugin_opt
 */
char *plugin_opt_flag_set(struct plugin_opt *popt);

/**
 * Helpers to initialize a connection to a plugin; we read from their
 * stdout, and write to their stdin.
 */
struct io_plan *plugin_stdin_conn_init(struct io_conn *conn,
                                       struct plugin *plugin);
struct io_plan *plugin_stdout_conn_init(struct io_conn *conn,
                                        struct plugin *plugin);

/**
 * Needed for I/O logging for plugin messages.
*/
struct logger *plugin_get_logger(struct plugin *plugin);

/**
 * Tells the plugin system the directory for builtin plugins.
 */
void plugins_set_builtin_plugins_dir(struct plugins *plugins,
				     const char *dir);

/* Is this option for a plugin? */
bool is_plugin_opt(const struct opt_table *ot);

/* Add this field if this ot is owned by a plugin */
void json_add_config_plugin(struct json_stream *stream,
			    const struct plugins *plugins,
			    const char *fieldname,
			    const struct opt_table *ot);

/* Attempt to setconfig an option in a plugin.  Calls success or fail, may be async! */
struct command_result *plugin_set_dynamic_opt(struct command *cmd,
					      const struct opt_table *ot,
					      const char *val,
					      struct command_result *(*success)
					      (struct command *,
					       const struct opt_table *,
					       const char *));
#endif /* LIGHTNING_LIGHTNINGD_PLUGIN_H */
