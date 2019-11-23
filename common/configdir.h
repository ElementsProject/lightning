#ifndef LIGHTNING_COMMON_CONFIGDIR_H
#define LIGHTNING_COMMON_CONFIGDIR_H
#include "config.h"
#include <ccan/tal/tal.h>

/* Helper for options which are tal() strings. */
char *opt_set_talstr(const char *arg, char **p);

/* Initial options setup */
void setup_option_allocators(void);

/* Parse minimal config options and files */
void initial_config_opts(const tal_t *ctx,
			 int argc, char *argv[],
			 char **config_filename,
			 char **config_dir,
			 char **rpc_filename);

/* Parse a specific include file */
void parse_include(const char *filename, bool must_exist, bool early);

/* For listconfigs to access. */
char *opt_ignore(const char *arg, void *unused);
char *opt_ignore_noarg(void *unused);

#endif /* LIGHTNING_COMMON_CONFIGDIR_H */
