#ifndef LIGHTNING_COMMON_STATUS_H
#define LIGHTNING_COMMON_STATUS_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/status_levels.h>

struct channel_id;
struct daemon_conn;
struct node_id;
struct per_peer_state;

/* Simple status reporting API. */
void status_setup_sync(int fd);
void status_setup_async(struct daemon_conn *master);

/* Send a printf-style debugging trace. */
void status_fmt(enum log_level level,
		const struct node_id *peer,
		const char *fmt, ...)
	PRINTF_FMT(3,4);

/* vprintf-style */
void status_vfmt(enum log_level level,
		 const struct node_id *peer,
		 const char *fmt, va_list ap);

/* Usually we only log the packet names, not contents. */
extern volatile bool logging_io;

/* This logs a debug summary if IO logging not enabled. */
void status_peer_io(enum log_level iodir,
		    const struct node_id *peer,
		    const u8 *p);
void status_io(enum log_level iodir,
	       const struct node_id *peer,
	       const char *who,
	       const void *data, size_t len);

/* Helpers */
#define status_trace(...)			\
	status_fmt(LOG_TRACE, NULL, __VA_ARGS__)
#define status_debug(...)			\
	status_fmt(LOG_DBG, NULL, __VA_ARGS__)
#define status_info(...)			\
	status_fmt(LOG_INFORM, NULL, __VA_ARGS__)
#define status_unusual(...)			\
	status_fmt(LOG_UNUSUAL, NULL, __VA_ARGS__)
#define status_broken( ...)			\
	status_fmt(LOG_BROKEN, NULL, __VA_ARGS__)

/* For daemons which handle multiple peers */
#define status_peer_trace(peer, ...)			\
	status_fmt(LOG_TRACE, (peer), __VA_ARGS__)
#define status_peer_debug(peer, ...)			\
	status_fmt(LOG_DBG, (peer), __VA_ARGS__)
#define status_peer_info(peer, ...)			\
	status_fmt(LOG_INFORM, (peer), __VA_ARGS__)
#define status_peer_unusual(peer, ...)			\
	status_fmt(LOG_UNUSUAL, (peer), __VA_ARGS__)
#define status_peer_broken(peer, ...)			\
	status_fmt(LOG_BROKEN, (peer), __VA_ARGS__)

/* Send a failure status code with printf-style msg, and exit. */
void status_failed(enum status_failreason code,
		   const char *fmt, ...) PRINTF_FMT(2,3) NORETURN;

/* Helper for master failures: sends STATUS_FATAL_MASTER_IO.
 * msg NULL == read failure. */
void master_badmsg(u32 type_expected, const u8 *msg) NORETURN;

void status_send(const u8 *msg TAKES);
void status_send_fatal(const u8 *msg TAKES) NORETURN;

/* Only for sync status! */
void status_send_fd(int fd);

/* Print BROKEN status: callback for dump_memleak. */
void memleak_status_broken(void *unused, const char *fmt, ...);

#endif /* LIGHTNING_COMMON_STATUS_H */
