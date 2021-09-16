#ifndef LIGHTNING_LIGHTNINGD_OPTIONS_H
#define LIGHTNING_LIGHTNINGD_OPTIONS_H
#include "config.h"

struct lightningd;

/* After this, early config file and cmdline options parsed. */
void handle_early_opts(struct lightningd *ld, int argc, char *argv[]);

/* After this we're in the .lightning dir, and we've parsed all options */
void handle_opts(struct lightningd *ld, int argc, char *argv[]);

/* Derive default color and alias from the pubkey. */
void setup_color_and_alias(struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_OPTIONS_H */
