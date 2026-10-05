/* Regression test for auditor finding F1 (2026-08-05 audit):
 * strset_iterate_() and strset_clear() recurse once per tree level, so
 * a deep enough tree (reachable via documented API calls alone)
 * overflows any fixed stack.  The child builds a maximally deep
 * "staircase" critbit chain, shrinks its stack rlimit, then iterates
 * and clears.
 *
 * On the recursive implementation the child dies with SIGSEGV; an
 * iterative implementation passes.  The verdict is TODO-wrapped while
 * the repair (explicit-stack traversal) is undecided.
 */
#include <ccan/strset/strset.h>
#include <ccan/strset/strset.c>
#include <ccan/tap/tap.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

/* Measured recursion frames are ~70 bytes at -O0 and ~16 bytes at -O2,
 * so 12000 levels need 190-840 KiB of stack: overflows the 128 KiB
 * rlimit set below with margin at any optimization level, but fits in
 * a default 8 MiB stack if the rlimit change is ineffective. */
#define DEPTH 12000

static bool count_cb(const char *member, void *p)
{
	unsigned int *n = p;
	(void)member;
	(*n)++;
	return true;
}

/* Returns 0 on success, 1 on wrong results; crashes when broken. */
static int child_scenario(void)
{
	static struct strset set;
	static char *strs[DEPTH];
	struct rlimit rl;
	unsigned int n = 0;
	int i, j;

	rl.rlim_cur = 128 * 1024;
	rl.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_STACK, &rl);

	strset_init(&set);
	/* Staircase chain: 8 split positions per byte, so the tree is a
	 * chain of depth DEPTH-1 using only ~DEPTH^2/16 bytes of keys. */
	for (i = 0; i < DEPTH; i++) {
		int len = i / 8 + 1;
		strs[i] = malloc(len + 1);
		if (!strs[i])
			abort();
		for (j = 0; j < len - 1; j++)
			strs[i][j] = '\xff';
		if (i % 8 == 0)
			strs[i][len-1] = 0x01;
		else
			strs[i][len-1] = (char)(unsigned char)(0xff << (i % 8));
		strs[i][len] = '\0';
		if (!strset_add(&set, strs[i]))
			abort();
	}
	if (strset_empty(&set))
		return 1;
	strset_iterate(&set, count_cb, &n);
	if (n != DEPTH)
		return 1;
	strset_clear(&set);
	if (!strset_empty(&set))
		return 1;

	for (i = 0; i < DEPTH; i++)
		free(strs[i]);
	return 0;
}

int main(void)
{
	pid_t pid;
	int status;

	plan_tests(1);
	alarm(120);

	pid = fork();
	if (pid == 0) {
		int r = child_scenario();
		/* Don't run atexit/flush: parent prints the TAP. */
		_exit(r);
	}
	if (waitpid(pid, &status, 0) != pid)
		abort();

	ok1(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	return exit_status();
}
