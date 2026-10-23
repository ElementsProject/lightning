/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_BREAKPOINT_H
#define CCAN_BREAKPOINT_H
#include <ccan/compiler/compiler.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

void breakpoint_init(void) COLD;
extern bool breakpoint_initialized;
extern bool breakpoint_under_debug;
extern pid_t breakpoint_pid;

/**
 * breakpoint - stop if running under the debugger.
 *
 * The first call detects the debugger via a SIGTRAP probe.  This is
 * not thread-safe: either call breakpoint_init() explicitly at
 * program start (before creating threads), or don't let first use
 * race.
 */
static inline void breakpoint(void)
{
	/* Detection state doesn't carry across fork(). */
	if (!breakpoint_initialized || breakpoint_pid != getpid())
		breakpoint_init();
	if (breakpoint_under_debug)
		kill(getpid(), SIGTRAP);
}
#endif /* CCAN_BREAKPOINT_H */
