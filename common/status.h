#ifndef LIGHTNING_COMMON_STATUS_H
#define LIGHTNING_COMMON_STATUS_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <common/htlc.h> /* For enum side */
#include <common/status_levels.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

struct daemon_conn;

/* Simple status reporting API. */
void status_setup_sync(int fd);
void status_setup_async(struct daemon_conn *master);

/* Convenient context, frees up after every status_update/failed */
extern const void *trc;

/* Send a printf-style debugging trace. */
void status_fmt(enum log_level level, const char *fmt, ...)
	PRINTF_FMT(2,3);

/* vprintf-style */
void status_vfmt(enum log_level level, const char *fmt, va_list ap);

/* Usually we only log the packet names, not contents. */
extern volatile bool logging_io;
void status_io(enum log_level iodir, const u8 *p);

/* Helpers */
#define status_debug(...)			\
	status_fmt(LOG_DBG, __VA_ARGS__)
#define status_info(...)			\
	status_fmt(LOG_INFORM, __VA_ARGS__)
#define status_unusual(...)			\
	status_fmt(LOG_UNUSUAL, __VA_ARGS__)
#define status_broken( ...)			\
	status_fmt(LOG_BROKEN, __VA_ARGS__)

/* FIXME: Transition */
#define status_trace(...) status_debug(__VA_ARGS__)

/* Send a failure status code with printf-style msg, and exit. */
void status_failed(enum status_failreason code,
		   const char *fmt, ...) PRINTF_FMT(2,3) NORETURN;

/* Helper for master failures: sends STATUS_FAIL_MASTER_IO.
 * msg NULL == read failure. */
void master_badmsg(u32 type_expected, const u8 *msg);

#endif /* LIGHTNING_COMMON_STATUS_H */
