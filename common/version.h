#ifndef LIGHTNING_COMMON_VERSION_H
#define LIGHTNING_COMMON_VERSION_H
#include "config.h"
#include <stdbool.h>

/* Add --version|-V option */
void opt_register_version(void);

const char *version(void);
/* check if the current version is a release version.
 *
 * Released versions are of form v[year].[month]?(.patch)* */
bool is_released_version(void);


#endif /* LIGHTNING_COMMON_VERSION_H */
