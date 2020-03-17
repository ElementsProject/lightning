#ifndef LIGHTNING_LIGHTNINGD_PLUGIN_H
#define LIGHTNING_LIGHTNINGD_PLUGIN_H
#include "config.h"
#include <ccan/intmap/intmap.h>
#include <ccan/io/io.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/take/take.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/tal.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/memleak.h>
#include <common/param.h>
#include <common/timeout.h>
#include <dirent.h>
#include <errno.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <unistd.h>


enum plugin_state {
	UNCONFIGURED,
	CONFIGURED
};

/**
 * A plugin may register any number of featurebits that should be added to
 * various messages as part of their manifest. The following enum enumerates
 * the possible locations the featurebits can be added to, and are used as
 * indices into the array of featurebits in the plugin struct itself.
 *
 * If you edit this make sure that there is a matching entry in the
 * `plugin_features_type_names[]` array in plugin.c.
 */
enum plugin_features_type {
	PLUGIN_FEATURES_NODE,
	PLUGIN_FEATURES_INIT,
	PLUGIN_FEATURES_INVOICE,
};
#define NUM_PLUGIN_FEATURES_TYPE (PLUGIN_FEATURES_INVOICE+1)

/**
 * A plugin, exposed as a stub so we can pass it as an argument.
 */
struct plugin {
	struct list_node list;

	pid_t pid;
	char *cmd;
	struct io_conn *stdin_conn, *stdout_conn;
	bool stop;
	struct plugins *plugins;
	const char **plugin_path;

	enum plugin_state plugin_state;

	/* If this plugin can be restarted without restarting lightningd */
	bool dynamic;

	/* Stuff we read */
	char *buffer;
	size_t used, len_read;

	/* Our json_streams. Since multiple streams could start
	 * returning data at once, we always service these in order,
	 * freeing once empty. */
	struct json_stream **js_arr;

	struct log *log;

	/* List of options that this plugin registered */
	struct list_head plugin_opts;

	const char **methods;

	/* Timer to add a timeout to some plugin RPC calls. Used to
	 * guarantee that `getmanifest` doesn't block indefinitely. */
	const struct oneshot *timeout_timer;

	/* An array of subscribed topics */
	char **subscriptions;

	/* Featurebits for various locations that the plugin
	 * registered. Indices correspond to the `plugin_features_type`
	 * enum. */
	u8 *featurebits[NUM_PLUGIN_FEATURES_TYPE];
};

/**
 * A collection of plugins, and some associated information.
 *
 * Mainly used as root context for calls in the plugin subsystem.
 */
struct plugins {
	struct list_head plugins;
	size_t pending_manifests;
	bool startup;

	/* Currently pending requests by their request ID */
	UINTMAP(struct jsonrpc_request *) pending_requests;
	struct log *log;
	struct log_book *log_book;

	struct lightningd *ld;
	const char *default_dir;
};

/* The value of a plugin option, which can have different types.
 * The presence of the integer and boolean values will depend of
 * the option type, but the string value will always be filled.
 */
struct plugin_opt_value {
	char *as_str;
	s64 *as_int;
	bool *as_bool;
};

/**
 * Simple storage for plugin options inbetween registering them on the
 * command line and passing them off to the plugin
 */
struct plugin_opt {
	struct list_node list;
	const char *name;
	const char *type;
	const char *description;
	struct plugin_opt_value *value;
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
 *
 * The dev_plugin_debug arg comes from --dev-debugger if DEVELOPER.
 */
void plugins_init(struct plugins *plugins, const char *dev_plugin_debug);

/**
 * Register a plugin for initialization and execution.
 *
 * @param plugins: Plugin context
 * @param path: The path of the executable for this plugin
 */
struct plugin *plugin_register(struct plugins *plugins, const char* path TAKES);

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
bool plugin_remove(struct plugins *plugins, const char *name);

/**
 * Kill a plugin process, with an error message.
 */
void plugin_kill(struct plugin *plugin, char *fmt, ...) PRINTF_FMT(2,3);

/**
 * Returns the plugin which registers the command with name {cmd_name}
 */
struct plugin *find_plugin_for_command(struct lightningd *ld,
				       const char *cmd_name);


/**
 * Send the configure message to all plugins.
 *
 * Once we've collected all the command line arguments we can go ahead
 * and send them over to the plugin. This finalizes the initialization
 * of the plugins and signals that lightningd is now ready to process
 * incoming JSON-RPC calls and messages.
 */
void plugins_config(struct plugins *plugins);

/**
 * Read and treat (populate options, methods, ...) the `getmanifest` response.
 */
bool plugin_parse_getmanifest_response(const char *buffer,
                                       const jsmntok_t *toks,
                                       const jsmntok_t *idtok,
                                       struct plugin *plugin);

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
 * Used by db hooks which can't have any other I/O while talking to plugin.
 *
 * Returns output of io_loop() (ie. whatever gets passed to io_break()
 * to end exclusive loop).
 */
void *plugin_exclusive_loop(struct plugin *plugin);

/**
 * Add a directory to the plugin path to automatically load plugins.
 */
char *add_plugin_dir(struct plugins *plugins, const char *dir,
		     bool error_ok);

/**
 * Clear all plugins registered so far.
 */
void clear_plugins(struct plugins *plugins);

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
struct log *plugin_get_log(struct plugin *plugin);

/* Pair of functions to detect if plugin destroys itself: must always
 * call both! */
struct plugin_destroyed *plugin_detect_destruction(const struct plugin *plugin);
bool was_plugin_destroyed(struct plugin_destroyed *destroyed);

/* Gather all the features of the given type that plugins registered. */
u8 *plugins_collect_featurebits(const tal_t *ctx, const struct plugins *plugins,
				enum plugin_features_type type);

#endif /* LIGHTNING_LIGHTNINGD_PLUGIN_H */
