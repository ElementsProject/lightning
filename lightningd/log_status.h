#ifndef LIGHTNING_LIGHTNINGD_LOG_STATUS_H
#define LIGHTNING_LIGHTNINGD_LOG_STATUS_H
#include "config.h"
#include <common/status_levels.h>
#include <lightningd/log.h>

/* Returns true (and writes it to log) if it's a status_log message. */
bool log_status_msg(struct log *log, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_LOG_STATUS_H */
