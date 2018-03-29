#ifndef LIGHTNING_COMMON_DAEMON_H
#define LIGHTNING_COMMON_DAEMON_H
#include "config.h"

/* Common setup for all daemons */
void daemon_setup(const char *argv0,
		  void (*backtrace_print)(const char *fmt, ...),
		  void (*backtrace_exit)(void));

/* Shutdown for a valgrind-clean exit (frees everything) */
void daemon_shutdown(void);

#endif /* LIGHTNING_COMMON_DAEMON_H */
