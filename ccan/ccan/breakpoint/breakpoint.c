/* CC0 (Public domain) - see LICENSE file for details
 *
 * Idea for implementation thanks to stackoverflow.com:
 *	http://stackoverflow.com/questions/3596781/detect-if-gdb-is-running
 */
#include <ccan/breakpoint/breakpoint.h>

bool breakpoint_initialized;
bool breakpoint_under_debug;
pid_t breakpoint_pid;

static volatile sig_atomic_t trapped;

/* This doesn't get called if we're under GDB. */
static void trap(int signum)
{
	trapped = true;
}

void breakpoint_init(void)
{
	struct sigaction old, new;
	sigset_t mask, oldmask;

	new.sa_handler = trap;
	new.sa_flags = 0;
	sigemptyset(&new.sa_mask);
	sigaction(SIGTRAP, &new, &old);

	/* If SIGTRAP is blocked, the probe would pend (and kill us when
	 * the caller restores its mask), not run the handler. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGTRAP);
	sigprocmask(SIG_UNBLOCK, &mask, &oldmask);

	trapped = false;
	kill(getpid(), SIGTRAP);

	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	sigaction(SIGTRAP, &old, NULL);

	breakpoint_pid = getpid();
	breakpoint_initialized = true;
	breakpoint_under_debug = !trapped;
}
