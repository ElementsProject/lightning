#include <ccan/rbuf/rbuf.h>
/* Include the C files directly. */
#include <ccan/rbuf/rbuf.c>
#include <ccan/tap/tap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

static bool test_realloc_fail;
static void *test_realloc(struct membuf *mb, void *buf, size_t n)
{
	if (test_realloc_fail)
		return NULL;
	return realloc(buf, n);
}

int main(void)
{
	struct rbuf in;
	char buf[4096];
	char *lines[100], *p;
	int i, fd = open("test/run.c", O_RDONLY), len;

	/* This is how many tests you plan to run */
	plan_tests(164);

	/* Grab ourselves for comparison. */
	len = read(fd, buf, sizeof(buf));
	buf[len] = '\0';
	lseek(fd, 0, SEEK_SET);

	for (i = 0, p = buf; *p; i++) {
		lines[i] = p;
		p = strchr(p, '\n');
		*p = '\0';
		p++;
	}
	lines[i] = NULL;

	rbuf_init(&in, fd, malloc(31), 31, test_realloc);
	ok1(in.fd == fd);
	ok1(membuf_num_space(&in.m) == 31);
	test_realloc_fail = true;
	p = rbuf_read_str(&in, '\n');
	ok1(p);
	ok1(strcmp(p, lines[0]) == 0);

	test_realloc_fail = false;
	p = rbuf_read_str(&in, '\n');
	ok1(p);
	ok1(strcmp(p, lines[1]) == 0);

	for (i = 2; lines[i]; i++) {
		ok1(p = rbuf_read_str(&in, '\n'));
		ok1(strcmp(p, lines[i]) == 0);
	}

	p = rbuf_read_str(&in, '\n');
	ok1(errno == 0);
	ok1(p == NULL);
	free(rbuf_cleanup(&in));

	/* Another way of reading the entire (text) file. */
	lseek(fd, 0, SEEK_SET);
	rbuf_init(&in, fd, NULL, 0, test_realloc);
	p = rbuf_read_str(&in, 0);
	ok1(p);
	ok1(strlen(p) == len);

	close(fd);
	p = rbuf_read_str(&in, 0);
	ok1(errno == EBADF);
	ok1(!p);
	free(rbuf_cleanup(&in));

	return exit_status();
}
