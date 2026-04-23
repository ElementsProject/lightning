#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_H

#include "config.h"
#include <plugins/libplugin.h>

/* Main bwatch state.
 *
 * bwatch is an out-of-process block scanner: it polls bitcoind, parses each
 * new block, and notifies lightningd (via the watchman RPCs) about chain
 * activity that lightningd has registered watches for.  Subsequent commits
 * add the watch hash tables, block history, and polling timer fields. */
struct bwatch {
	struct plugin *plugin;
	u32 poll_interval_ms;
};

/* Helper: retrieve the bwatch state from a plugin handle. */
struct bwatch *bwatch_of(struct plugin *plugin);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_H */
