#ifndef LIGHTNING_DAEMON_CONFIGDIR_H
#define LIGHTNING_DAEMON_CONFIGDIR_H
#include "config.h"
#include <ccan/tal/tal.h>

void configdir_register_opts(const tal_t *ctx,
			     char **config_dir, char **rpc_filename);

#endif /* LIGHTNING_DAEMON_CONFIGDIR_H */
