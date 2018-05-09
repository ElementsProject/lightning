#include <unistd.h>

static ssize_t partial_read(int fd, void *buf, size_t count)
{
	return read(fd, buf, 1);
}
static ssize_t full_read(int fd, void *buf, size_t count)
{
	return read(fd, buf, count);
}
#define read partial_read

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
	int i, fd = open("test/run.c", O_RDONLY);

	/* This is how many tests you plan to run */
	plan_tests(140);

	/* Grab ourselves for comparison. */
	buf[full_read(fd, buf, sizeof(buf))] = '\0';
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

	/* This exits depending on whether all tests passed */
	return exit_status();
}
