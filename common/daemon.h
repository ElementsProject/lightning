#ifndef LIGHTNING_COMMON_DAEMON_H
#define LIGHTNING_COMMON_DAEMON_H
#include "config.h"
#include <poll.h>

/* Common setup for all daemons */
void daemon_setup(const char *argv0,
		  void (*backtrace_print)(const char *fmt, ...),
		  void (*backtrace_exit)(void));

/* Exposed for lightningd's use. */
int daemon_poll(struct pollfd *fds, nfds_t nfds, int timeout);

/* Shutdown for a valgrind-clean exit (frees everything) */
void daemon_shutdown(void);

struct backtrace_state *backtrace_state;

#endif /* LIGHTNING_COMMON_DAEMON_H */
