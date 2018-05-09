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
	char buf[4096];
	char *lines[100], *p;
	int i, fd = open("test/run.c", O_RDONLY), len;

	/* This is how many tests you plan to run */
	plan_tests(144);

	/* Grab ourselves for comparison. */
	len = read(fd, buf, sizeof(buf));
	buf[len] = '\0';
	lseek(fd, SEEK_SET, 0);

	for (i = 0, p = buf; *p; i++) {
		lines[i] = p;
		p = strchr(p, '\n');
		*p = '\0';
		p++;
	}
	lines[i] = NULL;

	rbuf_init(&in, fd, malloc(31), 31);
	ok1(in.fd == fd);
	ok1(in.buf_end - in.buf == 31);
	p = rbuf_read_str(&in, '\n', NULL);
	ok1(p);
	ok1(strcmp(p, lines[0]) == 0);

	p = rbuf_read_str(&in, '\n', realloc);
	ok1(p);
	ok1(strcmp(p, lines[1]) == 0);

	for (i = 2; lines[i]; i++) {
		ok1(p = rbuf_read_str(&in, '\n', realloc));
		ok1(strcmp(p, lines[i]) == 0);
	}

	p = rbuf_read_str(&in, '\n', realloc);
	ok1(errno == 0);
	ok1(p == NULL);
	free(in.buf);

	/* Another way of reading the entire (text) file. */
	lseek(fd, SEEK_SET, 0);
	rbuf_init(&in, fd, NULL, 0);
	p = rbuf_read_str(&in, 0, realloc);
	ok1(p);
	ok1(strlen(p) == len);

	close(fd);
	p = rbuf_read_str(&in, 0, realloc);
	ok1(errno == EBADF);
	ok1(!p);
	free(in.buf);

	return exit_status();
}
