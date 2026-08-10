/* Regression test for: breakpoint_init() is not thread-safe.
 *
 * Fatal interleaving of two concurrent breakpoint_init() calls (both
 * reachable via the public breakpoint() on first use):
 *   A: sigaction(trap, &oldA=orig)
 *   B: sigaction(trap, &oldB=trap)   (B saves A's handler as "old")
 *   A: kill -> trap runs
 *   A: sigaction(oldA)               (disposition back to orig)
 *   B: kill -> SIGTRAP with original (default) disposition
 *      -> process terminated + core dump.
 *
 * Each child round resets breakpoint_initialized to re-enter the
 * uninitialized state, simulating many first-use races.  Fails against
 * the current code (a child is killed by SIGTRAP, usually in round 0).
 * Must pass after repair. */
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/breakpoint/breakpoint.c>
#include <ccan/tap/tap.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/wait.h>

#define NTHREADS 8
#define NITER 20000
#define NROUNDS 5

static void *hammer(void *arg)
{
	long i;
	(void)arg;
	for (i = 0; i < NITER; i++) {
		breakpoint_initialized = false;
		breakpoint_init();
	}
	return NULL;
}

int main(void)
{
	int round, crashed = 0;

	alarm(60);
	plan_tests(1);

	for (round = 0; round < NROUNDS && !crashed; round++) {
		pthread_t th[NTHREADS];
		pid_t pid;
		int status, i;

		pid = fork();
		if (pid == 0) {
			for (i = 0; i < NTHREADS; i++)
				pthread_create(&th[i], NULL, hammer, NULL);
			for (i = 0; i < NTHREADS; i++)
				pthread_join(th[i], NULL);
			exit(0);
		}
		waitpid(pid, &status, 0);
		if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTRAP)
			crashed = 1;
	}
	todo_start("breakpoint_init() thread race unresolved (audit F2)");
	ok1(!crashed);
	todo_end();
	return exit_status();
}
