#ifndef LIGHTNING_LIGHTNINGD_OPTIONS_H
#define LIGHTNING_LIGHTNINGD_OPTIONS_H
#include "config.h"
#include <ccan/tal/tal.h>

struct lightningd;

/* You can register additional options *after* this if you want. */
void register_opts(struct lightningd *ld);

/* After this, we're in the .lightning dir, config files parsed. */
void handle_opts(struct lightningd *ld, int argc, char *argv[]);

/* Derive default color and alias from the pubkey. */
void setup_color_and_alias(struct lightningd *ld);

/* Global to allow deprecated options. */
extern bool deprecated_apis;
#endif /* LIGHTNING_LIGHTNINGD_OPTIONS_H */
