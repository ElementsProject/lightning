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

/**
 * breakpoint - stop if running under the debugger.
 */
static inline void breakpoint(void)
{
	if (!breakpoint_initialized)
		breakpoint_init();
	if (breakpoint_under_debug)
		kill(getpid(), SIGTRAP);
}
#endif /* CCAN_BREAKPOINT_H */
