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

	ok1(rbuf_open(&in, "run-all-file", NULL, 0));
	/* Can't fill without realloc. */
	ok1(!rbuf_fill(&in, NULL));
	ok1(errno == ENOMEM);
	ok1(rbuf_fill(&in, realloc));
	/* But can't load in whole file. */
	ok1(!rbuf_fill_all(&in, NULL));
	ok1(errno == ENOMEM);
	ok1(rbuf_fill_all(&in, realloc));
	ok1(in.len == size);
	for (i = 0; i * sizeof(buf) < size; i++) {
		memset(buf, 0x42 + i, sizeof(buf));
		if (memcmp(buf, in.start, sizeof(buf)) != 0) {
			fail("Bad buffer contents");
			break;
		}
		rbuf_consume(&in, sizeof(buf));
	}
	free(in.buf);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
