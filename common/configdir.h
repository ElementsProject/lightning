#ifndef LIGHTNING_COMMON_CONFIGDIR_H
#define LIGHTNING_COMMON_CONFIGDIR_H
#include "config.h"
#include <ccan/tal/tal.h>

/* Helper for options which are tal() strings. */
char *opt_set_talstr(const char *arg, char **p);

void configdir_register_opts(const tal_t *ctx,
			     char **config_dir, char **rpc_filename);

#endif /* LIGHTNING_COMMON_CONFIGDIR_H */
