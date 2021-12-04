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
	char buf[4096], *p;
	int fd = open("test/run-term-eof.c", O_RDONLY), len;

	/* This is how many tests you plan to run */
	plan_tests(10);

	/* Grab ourselves for comparison. */
	len = read(fd, buf, sizeof(buf));
	buf[len] = '\0';
	lseek(fd, 0, SEEK_SET);

	/* We have exact-size buffer, which causes problems adding term. */
	rbuf_init(&in, fd, malloc(len), len, test_realloc);
	test_realloc_fail = true;
	p = rbuf_read_str(&in, 64); /* At symbol does not appear. */
	ok1(errno == ENOMEM);
	ok1(!p);
	/* This should succeed... */
	test_realloc_fail = false;
	p = rbuf_read_str(&in, 64);
	ok1(p);
	ok1(strcmp(p, buf) == 0);
	ok1(rbuf_start(&in) == p + strlen(p));
	free(rbuf_cleanup(&in));

	/* Try again. */
	lseek(fd, 0, SEEK_SET);
	rbuf_init(&in, fd, malloc(len), len, test_realloc);
	p = rbuf_read_str(&in, 64);
	ok1(p);
	ok1(strcmp(p, buf) == 0);
	ok1(rbuf_start(&in) == p + strlen(p));
	free(rbuf_cleanup(&in));

	/* Normal case, we get rbuf_start after nul */
	lseek(fd, 0, SEEK_SET);
	rbuf_init(&in, fd, NULL, 0, test_realloc);
	p = rbuf_read_str(&in, '^');
	ok1(p);
	ok1(rbuf_start(&in) == p + strlen(p) + 1);
	free(rbuf_cleanup(&in));

	return exit_status();
}
