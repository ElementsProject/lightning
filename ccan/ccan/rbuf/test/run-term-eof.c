#include <ccan/rbuf/rbuf.h>
/* Include the C files directly. */
#include <ccan/rbuf/rbuf.c>
#include <ccan/tap/tap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

int main(void)
{
	struct rbuf in;
	char buf[4096], *p;
	int fd = open("test/run-term-eof.c", O_RDONLY), len;

	/* This is how many tests you plan to run */
	plan_tests(6);

	/* Grab ourselves for comparison. */
	len = read(fd, buf, sizeof(buf));
	buf[len] = '\0';
	lseek(fd, SEEK_SET, 0);

	/* We have exact-size buffer, which causes problems adding term. */
	rbuf_init(&in, fd, malloc(len), len);
	p = rbuf_read_str(&in, 64, NULL); /* At symbol does not appear. */
	ok1(errno == ENOMEM);
	ok1(!p);
	/* This should succeed... */
	p = rbuf_read_str(&in, 64, realloc);
	ok1(p);
	ok1(strcmp(p, buf) == 0);
	free(in.buf);

	/* Try again. */
	lseek(fd, SEEK_SET, 0);
	rbuf_init(&in, fd, malloc(len), len);
	p = rbuf_read_str(&in, 64, realloc);
	ok1(p);
	ok1(strcmp(p, buf) == 0);
	free(in.buf);

	return exit_status();
}
