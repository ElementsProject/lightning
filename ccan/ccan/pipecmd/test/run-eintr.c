/* Regression test: a signal whose handler was installed without
 * SA_RESTART interrupts the parent's blocking read(execfail[0]);
 * pipecmdarr must not then report success for a command which does
 * not exist. */
#include <ccan/pipecmd/pipecmd.h>
/* Include the C files directly. */
#include <ccan/pipecmd/pipecmd.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

static void handler(int sig)
{
	(void)sig;
}

int main(void)
{
	struct sigaction sa;
	struct itimerval it, disarm;
	int i, false_success = 0;

	alarm(60);
	plan_tests(1);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sa.sa_flags = 0; /* no SA_RESTART */
	sigaction(SIGALRM, &sa, NULL);

	memset(&it, 0, sizeof(it));
	it.it_interval.tv_usec = 50;
	it.it_value.tv_usec = 50;
	memset(&disarm, 0, sizeof(disarm));

	for (i = 0; i < 2000; i++) {
		pid_t child;
		int status;

		setitimer(ITIMER_REAL, &it, NULL);
		child = pipecmd(NULL, NULL, NULL, "/doesnotexist", NULL);
		setitimer(ITIMER_REAL, &disarm, NULL);
		if (child != -1) {
			/* Reported success: did the command actually run? */
			if (waitpid(child, &status, 0) == child
			    && WIFEXITED(status) && WEXITSTATUS(status) == 127)
				false_success++;
		}
	}
	ok1(false_success == 0);

	return exit_status();
}
