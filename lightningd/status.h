

#ifndef LIGHTNING_LIGHTNINGD_STATUS_H
#define LIGHTNING_LIGHTNINGD_STATUS_H

#include "config.h"

#define LIGHTNINGD_STATUS_SYNCING (1 << 0)

const char *lightningd_status_to_str(int status);

#endif /* LIGHTNING_LIGHTNINGD_STATUS_H */

