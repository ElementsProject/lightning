/* CC0 (Public domain) - see LICENSE file for details
 *
 * Idea for implementation thanks to stackoverflow.com:
 *	http://stackoverflow.com/questions/3596781/detect-if-gdb-is-running
 */
#include <ccan/breakpoint/breakpoint.h>

bool breakpoint_initialized;
bool breakpoint_under_debug;

/* This doesn't get called if we're under GDB. */
static void trap(int signum)
{
	breakpoint_initialized = true;
}

void breakpoint_init(void)
{
	struct sigaction old, new;

	new.sa_handler = trap;
	new.sa_flags = 0;
	sigemptyset(&new.sa_mask);
	sigaction(SIGTRAP, &new, &old);
	kill(getpid(), SIGTRAP);
	sigaction(SIGTRAP, &old, NULL);

	if (!breakpoint_initialized) {
		breakpoint_initialized = true;
		breakpoint_under_debug = true;
	}
}
