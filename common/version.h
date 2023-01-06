#ifndef LIGHTNING_COMMON_VERSION_H
#define LIGHTNING_COMMON_VERSION_H
#include "config.h"
#include <stdbool.h>

char *version_and_exit(const void *unused);
const char *version(void);
/* check if the current version is a release version.
 *
 * Released versions are of form v[year].[month]?(.patch)* */
bool is_released_version(void);

#define opt_register_version()						\
	opt_register_early_noarg("--version|-V", version_and_exit, NULL, \
				 "Print version and exit")

#endif /* LIGHTNING_COMMON_VERSION_H */
