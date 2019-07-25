#ifndef LIGHTNING_COMMON_CONFIGDIR_H
#define LIGHTNING_COMMON_CONFIGDIR_H
#include "config.h"
#include <ccan/tal/tal.h>

/* Helper for options which are tal() strings. */
char *opt_set_talstr(const char *arg, char **p);

/* The default configuration dir: ~/.lightning */
char *default_configdir(const tal_t *ctx);

/* The default rpc filename: lightning-rpc */
char *default_rpcfile(const tal_t *ctx);

#endif /* LIGHTNING_COMMON_CONFIGDIR_H */
