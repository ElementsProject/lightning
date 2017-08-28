#ifndef LIGHTNING_DAEMON_OPTIONS_H
#define LIGHTNING_DAEMON_OPTIONS_H
#include "config.h"
#include <ccan/tal/tal.h>

struct lightningd_state;

/* You can register additional options *after* this if you want. */
void register_opts(struct lightningd_state *dstate);

/* After this, we're in the .lightning dir, config file parsed.
 * If we just created the dir, returns true.
 */
bool handle_opts(struct lightningd_state *dstate, int argc, char *argv[]);

#endif /* LIGHTNING_DAEMON_OPTIONS_H */
