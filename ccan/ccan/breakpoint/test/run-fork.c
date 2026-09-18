/* Regression test for: debugger-detection state is stale across fork().
 *
 * breakpoint_initialized/breakpoint_under_debug are plain globals
 * inherited by the child.  When the parent detected a debugger and then
 * forks, the child is NOT being traced (gdb's default
 * follow-fork-mode=parent detaches the child), but inherits
 * breakpoint_under_debug=true, so its breakpoint() sends itself SIGTRAP
 * with the default disposition: terminated + core dump, although it is
 * not running under a debugger.  Verified naturally under gdb 15.1
 * (see audit-findings/breakpoint.md F3); this test reproduces the exact
 * post-fork state directly.
 *
 * Fails against the current code (child killed by SIGTRAP).  Must pass
 * after repair. */
#include <unistd.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/breakpoint/breakpoint.c>
#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <sys/wait.h>

int main(void)
{
	pid_t pid;
	int status;

	alarm(10);
	plan_tests(1);

	/* State the child inherits after the parent ran breakpoint()
	 * under a debugger. */
	breakpoint_initialized = true;
	breakpoint_under_debug = true;

	pid = fork();
	if (pid == 0) {
		/* Child is not traced: breakpoint() must do nothing. */
		breakpoint();
		exit(0);
	}
	waitpid(pid, &status, 0);
	ok1(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	return exit_status();
}
