#ifndef LIGHTNING_COMMON_CONFIGDIR_H
#define LIGHTNING_COMMON_CONFIGDIR_H
#include "config.h"
#include <ccan/tal/tal.h>

/* Helper for options which are tal() strings. */
char *opt_set_talstr(const char *arg, char **p);

void configdir_register_opts(const tal_t *ctx,
			     char **config_dir, char **rpc_filename,
			     char **netname);

/* After arg parsing, sets rpc_filename if not explicitly set */
void config_finalize_rpc_name(const tal_t *ctx, char **rpc_filename,
			      const char *netname);

/* For each line: either argument string or NULL */
char **args_from_config_file(const tal_t *ctx, const char *configname);
#endif /* LIGHTNING_COMMON_CONFIGDIR_H */
