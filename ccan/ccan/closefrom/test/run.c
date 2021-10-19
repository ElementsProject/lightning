#include <ccan/closefrom/closefrom.h>
/* Include the C files directly. */
#include <ccan/closefrom/closefrom.c>
#include <ccan/tap/tap.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Open a pipe, do closefrom, check pipe no longer works.   */
static
int pipe_close(void)
{
	int fds[2];
	ssize_t wres;

	char buf = '\0';

	if (pipe(fds) < 0)
		return 0;

	/* Writing to the write end should succeed, the
	 * pipe is working.  */
	do {
		wres = write(fds[1], &buf, 1);
	} while ((wres < 0) && (errno == EINTR));
	if (wres < 0)
		return 0;

	closefrom(STDERR_FILENO + 1);

	/* Writing to the write end should fail because
	 * everything should be closed.  */
	do {
		wres = write(fds[1], &buf, 1);
	} while ((wres < 0) && (errno == EINTR));

	return (wres < 0) && (errno == EBADF);
}

/* Open a pipe, fork, do closefrom in child, read pipe from parent,
 * parent should see EOF.
 */
static
int fork_close(void)
{
	int fds[2];
	pid_t child;

	char buf;
	ssize_t rres;

	if (pipe(fds) < 0)
		return 0;

	child = fork();
	if (child < 0)
		return 0;

	if (child == 0) {
		/* Child.  */
		closefrom(STDERR_FILENO + 1);
		_exit(0);
	} else {
		/* Parent.  */

		/* Close write end of pipe.  */
		close(fds[1]);

		do {
			rres = read(fds[0], &buf, 1);
		} while ((rres < 0) && (errno == EINTR));

		/* Should have seen EOF.  */
		if (rres != 0)
			return 0;

		/* Clean up.  */
		waitpid(child, NULL, 0);
		closefrom(STDERR_FILENO + 1);
	}

	return 1;
}
/* Open a pipe, fork, in child set the write end to fd #3,
 * in parent set the read end to fd #3, send a byte from
 * child to parent, check.
 */
static
int fork_communicate(void)
{
	int fds[2];
	pid_t child;

	char wbuf = 42;
	char rbuf;
	ssize_t rres;
	ssize_t wres;

	int status;

	if (pipe(fds) < 0)
		return 0;

	child = fork();
	if (child < 0)
		return 0;

	if (child == 0) {
		/* Child.  */

		/* Move write end to fd #3.  */
		if (fds[1] != 3) {
			if (dup2(fds[1], 3) < 0)
				_exit(127);
			close(fds[1]);
			fds[1] = 3;
		}

		closefrom(4);

		do {
			wres = write(fds[1], &wbuf, 1);
		} while ((wres < 0) && (errno == EINTR));
		if (wres < 0)
			_exit(127);

		_exit(0);
	} else {
		/* Parent.  */

		/* Move read end to fd #3.  */
		if (fds[0] != 3) {
			if (dup2(fds[0], 3) < 0)
				return 0;
			close(fds[0]);
			fds[0] = 3;
		}

		closefrom(4);

		/* Wait for child to finish.  */
		waitpid(child, &status, 0);
		if (!WIFEXITED(status))
			return 0;
		if (WEXITSTATUS(status) != 0)
			return 0;

		/* Read 1 byte.  */
		do {
			rres = read(fds[0], &rbuf, 1);
		} while ((rres < 0) && (errno == EINTR));
		if (rres < 0)
			return 0;
		if (rres != 1)
			return 0;
		/* Should get same byte as what was sent.  */
		if (rbuf != wbuf)
			return 0;

		/* Next attempt to read should EOF.  */
		do {
			rres = read(fds[0], &rbuf, 1);
		} while ((rres < 0) && (errno == EINTR));
		if (rres < 0)
			return 0;
		/* Should EOF.  */
		if (rres != 0)
			return 0;

	}

	/* Clean up.  */
	close(fds[0]);
	return 1;
}

int main(void)
{
	/* Limit closefrom.  */
	closefrom_limit(0);

	/* This is how many tests you plan to run */
	plan_tests(3);

	ok1(pipe_close());
	ok1(fork_close());
	ok1(fork_communicate());

	/* This exits depending on whether all tests passed */
	return exit_status();
}
