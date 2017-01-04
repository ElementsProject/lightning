#ifndef LIGHTNING_DAEMON_OPTIONS_H
#define LIGHTNING_DAEMON_OPTIONS_H
#include "config.h"
#include <ccan/tal/tal.h>

struct lightningd_state;

/* After this, we're in the .lightning dir, config file parsed. */
void handle_opts(struct lightningd_state *dstate, int argc, char *argv[]);

#endif /* LIGHTNING_DAEMON_OPTIONS_H */
