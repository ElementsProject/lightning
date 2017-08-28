#ifndef LIGHTNING_LIGHTNINGD_OPTIONS_H
#define LIGHTNING_LIGHTNINGD_OPTIONS_H
#include "config.h"
#include <ccan/tal/tal.h>

struct lightningd;

/* You can register additional options *after* this if you want. */
void register_opts(struct lightningd *ld);

/* After this, we're in the .lightning dir, config file parsed.
 * If we just created the dir, returns true.
 */
bool handle_opts(struct lightningd *ld, int argc, char *argv[]);

#endif /* LIGHTNING_LIGHTNINGD_OPTIONS_H */
