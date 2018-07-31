#ifndef LIGHTNING_LIGHTNINGD_STATUS_H
#define LIGHTNING_LIGHTNINGD_STATUS_H

#include "config.h"

enum lightningd_status {
	LIGHTNINGD_STATUS_INITIALIZING,
	LIGHTNINGD_STATUS_SYNCING,
	LIGHTNINGD_STATUS_READY,
};

const char *lightningd_status_to_str(enum lightningd_status status);

#endif /* LIGHTNING_LIGHTNINGD_STATUS_H */
