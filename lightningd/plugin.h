#ifndef LIGHTNING_LIGHTNINGD_PLUGIN_H
#define LIGHTNING_LIGHTNINGD_PLUGIN_H
#include "config.h"
#include <ccan/take/take.h>
#include <ccan/tal/tal.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/log.h>

/**
 * A collection of plugins, and some associated information.
 *
 * Mainly used as root context for calls in the plugin subsystem.
 */
struct plugins;

/**
 * A plugin, exposed as a stub so we can pass it as an argument.
 */
struct plugin;

/**
 * Simple storage for plugin options inbetween registering them on the
 * command line and passing them off to the plugin
 */
struct plugin_opt;

/**
 * Create a new plugins context.
 */
struct plugins *plugins_new(const tal_t *ctx, struct log_book *log_book,
			    struct lightningd *ld);

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
void plugin_register(struct plugins *plugins, const char* path TAKES);


/**
 * Remove a plugin registered for initialization.
 *
 * @param plugins: Plugin context
 * @param arg: The basename or fullname of the executable for this plugin
 */
bool plugin_remove(struct plugins *plugins, const char *name);

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
		     bool nonexist_ok);

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

#endif /* LIGHTNING_LIGHTNINGD_PLUGIN_H */
