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

bool parse_ipaddr(const char *arg, struct ipaddr *addr, u16 port);

/* Derive default color and alias from the pubkey. */
void setup_color_and_alias(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_OPTIONS_H */
