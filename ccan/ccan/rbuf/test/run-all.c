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
	int i, size, fd = open("run-all-file", O_WRONLY|O_CREAT, 0600);

	/* This is how many tests you plan to run */
	plan_tests(8);

	/* Make sure we're bigger than a single buffer! */
	size = rbuf_good_size(fd)*2;
	for (i = 0; i * sizeof(buf) < size; i++) {
		memset(buf, 0x42 + i, sizeof(buf));
		write(fd, buf, sizeof(buf));
	}
	close(fd);

	ok1(rbuf_open(&in, "run-all-file", NULL, 0, test_realloc));
	/* Can't fill if realloc fails. */
	test_realloc_fail = true;
	ok1(!rbuf_fill(&in));
	ok1(errno == ENOMEM);
	test_realloc_fail = false;
	ok1(rbuf_fill(&in));
	/* But can't load in whole file. */
	test_realloc_fail = true;
	ok1(!rbuf_fill_all(&in));
	ok1(errno == ENOMEM);
	test_realloc_fail = false;
	ok1(rbuf_fill_all(&in));
	ok1(rbuf_len(&in) == size);
	for (i = 0; i * sizeof(buf) < size; i++) {
		memset(buf, 0x42 + i, sizeof(buf));
		if (memcmp(buf, rbuf_start(&in), sizeof(buf)) != 0) {
			fail("Bad buffer contents");
			break;
		}
		rbuf_consume(&in, sizeof(buf));
	}
	free(rbuf_cleanup(&in));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
