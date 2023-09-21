#ifndef LIGHTNING_COMMON_DAEMON_H
#define LIGHTNING_COMMON_DAEMON_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <poll.h>

/* Common setup for all daemons */
void daemon_setup(const char *argv0,
		  void (*backtrace_print)(const char *fmt, ...),
		  void (*backtrace_exit)(void));

/* Exposed for lightningd's use. */
int daemon_poll(struct pollfd *fds, nfds_t nfds, int timeout);

/* Print a backtrace to stderr, and via backtrace_print */
void send_backtrace(const char *why);

/* Try to extract a name for this function/var/etc */
const char *backtrace_symname(const tal_t *ctx, const void *addr);

/* Shutdown for a valgrind-clean exit (frees everything) */
void daemon_shutdown(void);

/* If --developer is set, set up extra developer checks, kick in a
 * debugger if they set --debugger, and return true.   */
bool daemon_developer_mode(char *argv[]);

#endif /* LIGHTNING_COMMON_DAEMON_H */
