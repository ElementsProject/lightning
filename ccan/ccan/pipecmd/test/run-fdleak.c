#include <ccan/pipecmd/pipecmd.h>
/* Include the C files directly. */
#include <ccan/pipecmd/pipecmd.c>
#include <ccan/tap/tap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
	pid_t child;
	int outfd, status;
	char buf[5] = "test";

	/* We call ourselves, to test pipe. */
	if (argc == 2) {
		if (write(STDOUT_FILENO, buf, sizeof(buf)) != sizeof(buf))
				exit(1);
		exit(0);
	}

	/* This is how many tests you plan to run */
	plan_tests(13);
	child = pipecmd(NULL, &outfd, NULL, argv[0], "out", NULL);
	if (!ok1(child > 0))
		exit(1);
	ok1(read(outfd, buf, sizeof(buf)) == sizeof(buf));
	ok1(memcmp(buf, "test", sizeof(buf)) == 0);
	ok1(waitpid(child, &status, 0) == child);
	ok1(WIFEXITED(status));
	ok1(WEXITSTATUS(status) == 0);

	/* No leaks! */
	ok1(close(outfd) == 0);
	ok1(close(outfd) == -1 && errno == EBADF);
	ok1(close(++outfd) == -1 && errno == EBADF);
	ok1(close(++outfd) == -1 && errno == EBADF);
	ok1(close(++outfd) == -1 && errno == EBADF);
	ok1(close(++outfd) == -1 && errno == EBADF);
	ok1(close(++outfd) == -1 && errno == EBADF);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
