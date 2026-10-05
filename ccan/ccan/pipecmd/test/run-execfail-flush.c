/* Regression test: on exec failure the child calls exit(127) instead of
 * _exit(127), so it flushes the parent's inherited stdio buffers a second
 * time (and runs atexit handlers) when an output stream is preserved. */
#include <unistd.h>
#include <ccan/pipecmd/pipecmd.h>
/* Include the C files directly. */
#include <ccan/pipecmd/pipecmd.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>


#if defined(__has_include)
#if __has_include(<valgrind/valgrind.h>)
#include <valgrind/valgrind.h>
#define HAVE_VALGRIND_H 1
#endif
#endif

int main(void)
{
#ifdef HAVE_VALGRIND_H
	/* valgrind perturbs the child-exit/fd-count behavior this test
	 * measures. */
	if (RUNNING_ON_VALGRIND) {
		plan_skip_all("not meaningful under valgrind");
		return exit_status();
	}
#endif
	char template[] = "/tmp/run-execfail-flush.XXXXXX";
	int fd, oldfd, saved_errno;
	pid_t child;
	FILE *f;
	char buf[64];
	size_t n;

	alarm(10);
	plan_tests(4);

	fd = mkstemp(template);
	ok1(fd >= 0);

	/* Mug stdout with a file: fully buffered, so the printf below
	 * stays in the stdio buffer across fork(). */
	oldfd = dup(STDOUT_FILENO);
	if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO)
		exit(1);
	close(fd);
	printf("unflushed-data"); /* no newline: stays buffered */

	errno = 0;
	child = pipecmd(NULL, &pipecmd_preserve, NULL, "/doesnotexist", NULL);
	saved_errno = errno;

	/* Parent's own flush, then restore stdout for TAP output. */
	fflush(stdout);
	if (dup2(oldfd, STDOUT_FILENO) != STDOUT_FILENO)
		exit(1);
	close(oldfd);

	ok1(child == -1);
	ok1(saved_errno == ENOENT);

	f = fopen(template, "r");
	n = fread(buf, 1, sizeof(buf) - 1, f);
	buf[n] = '\0';
	fclose(f);
	unlink(template);

	/* The child must not have flushed the inherited buffer. */
	ok1(strcmp(buf, "unflushed-data") == 0);

	return exit_status();
}
