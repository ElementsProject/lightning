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

	/* This is how many tests you plan to run */
	plan_tests(5);

	ok1(!rbuf_open(&in, "nonexistent-file", NULL, 0, NULL));
	ok1(errno == ENOENT);
	ok1(rbuf_open(&in, "test/run-open.c", NULL, 0, NULL));
	ok1(close(in.fd) == 0);
	/* If this fails to stat, it should fall back */
	ok1(rbuf_good_size(in.fd) == 4096);

	return exit_status();
}
