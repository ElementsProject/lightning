#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tap/tap.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <limits.h>
#include <sys/wait.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static ssize_t test_write(int fd, const void *buf, size_t count);
#define write test_write
#include <ccan/read_write_all/read_write_all.c>
#undef write

static ssize_t write_return;

static ssize_t test_write(int fd, const void *buf, size_t count)
{
	if (write_return == 0) {
		errno = ENOSPC;
		return 0;
	}

	if (write_return < 0) {
		errno = -write_return;
		/* Don't return EINTR more than once! */
		if (errno == EINTR)
			write_return = count;
		return -1;
	}

	if (write_return < count)
		return write_return;
	return count;
}

#define BUFSZ 1024

int main(int argc, char *argv[])
{
	char *buffer;

	buffer = malloc(BUFSZ);
	plan_tests(8);

	write_return = -ENOSPC;
	ok1(!write_all(100, buffer, BUFSZ));
	ok1(errno == ENOSPC);

	write_return = -EINTR;
	ok1(write_all(100, buffer, BUFSZ));
	ok1(errno == EINTR);

	write_return = 1;
	errno = 0;
	ok1(write_all(100, buffer, BUFSZ));
	ok1(errno == 0);

	write_return = BUFSZ;
	ok1(write_all(100, buffer, BUFSZ));
	ok1(errno == 0);
	free(buffer);

	return exit_status();
}
