#define CCAN_LIKELY_DEBUG 1
#include <ccan/likely/likely.c>
#include <ccan/likely/likely.h>
#include <ccan/tap/tap.h>
#include <stdlib.h>

static bool one_seems_likely(unsigned int val)
{
	if (likely(val == 1))
		return true;
	return false;
}

static bool one_seems_unlikely(unsigned int val)
{
	if (unlikely(val == 1))
		return true;
	return false;
}

static bool likely_one_unlikely_two(unsigned int val1, unsigned int val2)
{
	/* Same line, check we don't get confused! */
	if (likely(val1 == 1) && unlikely(val2 == 2))
		return true;
	return false;
}

int main(void)
{
	char *bad;

	plan_tests(14);

	/* Correct guesses. */
	one_seems_likely(1);
	ok1(likely_stats(0, 90) == NULL);
	one_seems_unlikely(2);
	ok1(likely_stats(0, 90) == NULL);

	/* Incorrect guesses. */
	one_seems_likely(0);
	one_seems_likely(2);
	/* Hasn't been hit 4 times, so this fails */
	ok1(!likely_stats(4, 90));
	bad = likely_stats(3, 90);
	ok(strends(bad, "run-debug.c:9:likely(val == 1) correct 33% (1/3)"),
	   "likely_stats returned %s", bad);
	free(bad);

	/* Nothing else above 90% */
	ok1(!likely_stats(0, 90));

	/* This should get everything. */
	bad = likely_stats(0, 100);
	ok(strends(bad, "run-debug.c:16:unlikely(val == 1) correct 100% (1/1)"),
	   "likely_stats returned %s", bad);
	free(bad);

	/* Nothing left (table is actually cleared) */
	ok1(!likely_stats(0, 100));

	/* Make sure unlikely works */
	one_seems_unlikely(0);
	one_seems_unlikely(2);
	one_seems_unlikely(1);

	bad = likely_stats(0, 90);
	ok(strends(bad, "run-debug.c:16:unlikely(val == 1) correct 66% (2/3)"),
	   "likely_stats returned %s", bad);
	free(bad);
	ok1(!likely_stats(0, 100));

	likely_one_unlikely_two(1, 1);
	likely_one_unlikely_two(1, 1);
	likely_one_unlikely_two(1, 1);
	ok1(!likely_stats(0, 90));
	likely_one_unlikely_two(1, 2);

	bad = likely_stats(0, 90);
	ok(strends(bad, "run-debug.c:24:unlikely(val2 == 2) correct 75% (3/4)"),
	   "likely_stats returned %s", bad);
	free(bad);
	bad = likely_stats(0, 100);
	ok(strends(bad, "run-debug.c:24:likely(val1 == 1) correct 100% (4/4)"),
	   "likely_stats returned %s", bad);
	free(bad);

	ok1(!likely_stats(0, 100));

	/* Check that reset works! */
	one_seems_unlikely(0);
	one_seems_unlikely(2);
	one_seems_unlikely(1);
	likely_stats_reset();

	ok1(!likely_stats(0, 100));

	exit(exit_status());
}

/* Fools ccanlint: it doesn't think we use str, htable or hash. */
#include <ccan/hash/hash.h>
#include <ccan/htable/htable.h>
#include <ccan/str/str.h>
