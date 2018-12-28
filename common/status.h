#ifndef LIGHTNING_COMMON_STATUS_H
#define LIGHTNING_COMMON_STATUS_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <ccan/take/take.h>
#include <common/status_levels.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

struct channel_id;
struct daemon_conn;

/* Simple status reporting API. */
void status_setup_sync(int fd);
void status_setup_async(struct daemon_conn *master);

/* Send a printf-style debugging trace. */
void status_fmt(enum log_level level, const char *fmt, ...)
	PRINTF_FMT(2,3);

/* vprintf-style */
void status_vfmt(enum log_level level, const char *fmt, va_list ap);

/* Usually we only log the packet names, not contents. */
extern volatile bool logging_io;
void status_peer_io(enum log_level iodir, const u8 *p);
void status_io(enum log_level iodir, const char *who,
	       const void *data, size_t len);

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

/* Helper for master failures: sends STATUS_FATAL_MASTER_IO.
 * msg NULL == read failure. */
void master_badmsg(u32 type_expected, const u8 *msg) NORETURN;

void status_send(const u8 *msg TAKES);
void status_send_fatal(const u8 *msg TAKES, int fd1, int fd2) NORETURN;
#endif /* LIGHTNING_COMMON_STATUS_H */
