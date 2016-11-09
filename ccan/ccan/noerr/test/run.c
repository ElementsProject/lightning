#include <ccan/noerr/noerr.h>
#include <ccan/tap/tap.h>
#include <ccan/noerr/noerr.c>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>

int main(void)
{
	const char *name = "noerr.file";
	int fd;
	FILE *fp;

	plan_tests(16);
	/* Should fail to unlink. */
	ok1(unlink(name) != 0);
	ok1(errno == ENOENT);

	/* This one should not set errno. */
	errno = 100;
	ok1(unlink_noerr(name) == ENOENT);
	ok1(errno == 100);

	/* Should fail to close. */
	ok1(close(-1) != 0);
	ok1(errno == EBADF);

	/* This one should not set errno. */
	errno = 100;
	ok1(close_noerr(-1) == EBADF);
	ok1(errno == 100);

	/* Test successful close/unlink doesn't hit errno either. */
	fd = open(name, O_WRONLY|O_CREAT|O_EXCL, 0600);
	assert(fd >= 0);

	errno = 100;
	ok1(close_noerr(fd) == 0);
	ok1(errno == 100);

	errno = 100;
	ok1(unlink_noerr(name) == 0);
	ok1(errno == 100);

	/* Test failing fclose */
	fp = fopen(name, "wb");
	assert(fp);
	close(fileno(fp));
	ok1(fclose_noerr(fp) == EBADF);

	/* Test successful fclose */
	fp = fopen(name, "wb");
	assert(fp);

	errno = 100;
	ok1(fclose_noerr(fp) == 0);
	ok1(errno == 100);
	unlink(name);

	errno = 101;
	free_noerr(malloc(7));
	ok1(errno == 101);

	return exit_status();
}
