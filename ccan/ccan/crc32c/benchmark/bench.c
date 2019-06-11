#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <ccan/crc32c/crc32c.c>
#include <assert.h>
#include <ccan/err/err.h>

#define RUNS 65536

int main(int argc, char *argv[])
{
	void *p;
	struct timeabs start, end;
	size_t len, runs;
	uint64_t sums = 0;
	bool sw = false, hw = false;

	if (argv[1]) {
		if (streq(argv[1], "--software")) {
			sw = true;
			argv++;
			argc--;

		} else if (streq(argv[1], "--hardware")) {
			hw = true;
			argv++;
			argc--;
		}
	}

	if (argc < 2 || (runs = atol(argv[1])) == 0)
		errx(1, "Usage: bench <num-runs> [<file>]");

	p = grab_file(NULL, argv[2]);
	if (!p)
		err(1, "Reading %s", argv[2] ? argv[2] : "<stdin>");
	len = tal_count(p) - 1;
	start = time_now();
	if (sw) {
		for (size_t i = 0; i < runs; i++)
			sums += crc32c_sw(0, p, len);
	} else if (hw) {
		for (size_t i = 0; i < runs; i++)
			sums += crc32c_hw(0, p, len);
	} else {
		for (size_t i = 0; i < runs; i++)
			sums += crc32c(0, p, len);
	}
	end = time_now();

	assert(sums % runs == 0);
	printf("%u usec for %zu bytes, sum=%08x\n",
	       (int)time_to_usec(time_divide(time_between(end, start), runs)),
	       len,
	       (unsigned int)(sums / runs));
	return 0;
}
