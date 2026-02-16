#ifndef LIGHTNING_PLUGINS_ASKRENE_CHILD_CHILD_LOG_H
#define LIGHTNING_PLUGINS_ASKRENE_CHILD_CHILD_LOG_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/status_levels.h>

/* Logs this, and also returns the string allocated off ctx */
const char *child_log(const tal_t *ctx,
		      enum log_level level,
		      const char *fmt,
		      ...)
	PRINTF_FMT(3,4);

/* BROKEN variant. */
void child_err(const char *fmt, ...)
	PRINTF_FMT(1, 2) NORETURN;

/* At initialization, we set this to the fd for child_log() to write to */
void set_child_log_fd(int fd);
#endif /* LIGHTNING_PLUGINS_ASKRENE_CHILD_CHILD_LOG_H */
