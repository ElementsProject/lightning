#ifndef LIGHTNING_VERSION_H
#define LIGHTNING_VERSION_H
#include "config.h"
#include <ccan/opt/opt.h>

char *version_and_exit(const void *unused);

#define opt_register_version()						\
	opt_register_noarg("--version|-V", version_and_exit, NULL,	\
			   "print version to standard output and exit")

#endif /* LIGHTNING_VERSION_H */
