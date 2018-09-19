#ifndef LIGHTNING_LIGHTNINGD_PLUGIN_H
#define LIGHTNING_LIGHTNINGD_PLUGIN_H
#include "config.h"
#include <ccan/take/take.h>
#include <ccan/tal/tal.h>

/**
 * A collection of plugins, and some associated information.
 *
 * Mainly used as root context for calls in the plugin subsystem.
 */
struct plugins;

/**
 * Create a new plugins context.
 */
struct plugins *plugins_new(const tal_t *ctx);

/**
 * Initialize the registered plugins.
 *
 * Initialization includes spinning up the plugins, reading their init messages,
 * and registering the JSON-RPC passthrough and command line arguments. In order
 * to read the init messages from the plugins we spin up our own io_loop that
 * exits once all plugins have responded.
 */
void plugins_init(struct plugins *plugins);

/**
 * Register a plugin for initialization and execution.
 *
 * @param plugins: Plugin context
 * @param path: The path of the executable for this plugin
 */
void plugin_register(struct plugins *plugins, const char* path TAKES);

#endif /* LIGHTNING_LIGHTNINGD_PLUGIN_H */
