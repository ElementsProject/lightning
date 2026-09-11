#include <ccan/rbuf/rbuf.h>
/* Include the C files directly. */
#include <ccan/rbuf/rbuf.c>
#include <ccan/tap/tap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

/* Regression test: rbuf.h documents for rbuf_fill:
 * "If there is nothing more to read, it will return NULL with errno set
 * to 0", and the documented example loops while (rbuf_fill(&in)).
 * The current code returns rbuf_start() (non-NULL) at EOF, so that loop
 * never terminates. */
int main(void)
{
	struct rbuf in;
	int fd;
	unsigned int iters;
	void *p;

	plan_tests(7);
	alarm(10);

	fd = open("run-fill-eof-file", O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (write(fd, "hello world\n", 12) != 12)
		abort();
	close(fd);
	fd = open("run-fill-eof-empty", O_WRONLY|O_CREAT|O_TRUNC, 0600);
	close(fd);

	/* The documented loop pattern must terminate at EOF. */
	if (!rbuf_open(&in, "run-fill-eof-file", NULL, 0, membuf_realloc))
		abort();
	errno = EDOM;
	iters = 0;
	while (rbuf_fill(&in)) {
		rbuf_consume(&in, rbuf_len(&in));
		if (++iters > 100)
			break;
	}
	ok1(iters <= 100);
	ok1(errno == 0);
	close(in.fd);
	free(rbuf_cleanup(&in));

	/* Direct: after the last byte is consumed, rbuf_fill is NULL/EOF. */
	fd = open("run-fill-eof-file", O_RDONLY);
	rbuf_init(&in, fd, NULL, 0, membuf_realloc);
	p = rbuf_fill(&in);
	ok1(p != NULL);
	rbuf_consume(&in, rbuf_len(&in));
	errno = EDOM;
	p = rbuf_fill(&in);
	ok1(p == NULL);
	ok1(errno == 0);
	close(in.fd);
	free(rbuf_cleanup(&in));

	/* Empty file: the very first fill is already EOF. */
	fd = open("run-fill-eof-empty", O_RDONLY);
	rbuf_init(&in, fd, NULL, 0, membuf_realloc);
	errno = EDOM;
	p = rbuf_fill(&in);
	ok1(p == NULL);
	ok1(errno == 0);
	close(in.fd);
	free(rbuf_cleanup(&in));

	unlink("run-fill-eof-file");
	unlink("run-fill-eof-empty");

	return exit_status();
}
