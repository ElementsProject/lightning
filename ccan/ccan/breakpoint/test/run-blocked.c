/* Regression test for: breakpoint_init() does not handle SIGTRAP being
 * blocked in the calling thread.
 *
 * With SIGTRAP blocked, the kill(getpid(), SIGTRAP) in breakpoint_init
 * only *pends* the signal; the trap handler never runs, so the module
 * concludes "under debugger" (wrong: no debugger is attached), and the
 * pending SIGTRAP is delivered later - when the caller restores its
 * signal mask - to the caller's original disposition (default:
 * terminate + core dump).
 *
 * Fails against the current code: the second ok1 fails
 * (breakpoint_under_debug == true) and the process is then killed by
 * SIGTRAP when the mask is restored.  Must pass after repair. */
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/breakpoint/breakpoint.c>
#include <ccan/tap/tap.h>
#include <signal.h>
#include <stdlib.h>

int main(void)
{
	sigset_t set, oset;

	alarm(10);
	plan_tests(3);

	sigemptyset(&set);
	sigaddset(&set, SIGTRAP);
	ok1(sigprocmask(SIG_BLOCK, &set, &oset) == 0);

	/* Not under a debugger; blocking SIGTRAP must not change that. */
	breakpoint();
	ok1(breakpoint_initialized && !breakpoint_under_debug);

	/* Restoring the caller's signal mask must be safe: the module
	 * must not leave a SIGTRAP pending behind the caller's back. */
	sigprocmask(SIG_SETMASK, &oset, NULL);
	ok1(true);

	return exit_status();
}
