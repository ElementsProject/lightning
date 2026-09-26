/* Temporary auditor regression test (kimi-code audit, 2026-08-05).
 * Proves: membuf_prepare_space_() growth arithmetic
 * (mb->max_elems + num_extra) * elemsize (ccan/membuf/membuf.c:45-46)
 * overflows size_t, so expandfn is called with a tiny wrapped size,
 * "succeeds", and the documented failure check (membuf_num_space() <
 * num_extra, membuf.h:163-165) reports SUCCESS with a far-too-small
 * buffer.  Fails against current code; must pass after repair.
 * The test is memory-safe even when failing: it never writes into the
 * bogus buffer.
 */
#include <ccan/membuf/membuf.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

/* Include the C file directly. */
#include <ccan/membuf/membuf.c>
#include <ccan/tap/tap.h>

static void *fail_expand(struct membuf *mb, void *elems, size_t newsize)
{
	(void)mb; (void)elems; (void)newsize;
	return NULL;
}

int main(void)
{
	MEMBUF(int) mb;
	/* (4 + num_extra) * sizeof(int) wraps to 16 on LP64 and ILP32. */
	size_t num_extra = (SIZE_MAX / sizeof(int)) + 1;

	plan_tests(6);
	alarm(10);

	/* Control 1: ordinary growth still works and is reported. */
	membuf_init(&mb, malloc(4 * sizeof(int)), 4, membuf_realloc);
	membuf_prepare_space(&mb, 8);
	ok1(membuf_num_space(&mb) >= 8);
	free(membuf_cleanup(&mb));

	/* Control 2: genuine expandfn failure is reported as documented. */
	membuf_init(&mb, malloc(4 * sizeof(int)), 4, fail_expand);
	errno = 0;
	membuf_prepare_space(&mb, 8);
	ok1(membuf_num_space(&mb) < 8);
	ok1(errno == ENOMEM);
	free(membuf_cleanup(&mb));

	/* The defect: an impossible growth request must FAIL (ENOMEM,
	 * num_space < num_extra), not "succeed" with a wrapped-size
	 * allocation. */
	membuf_init(&mb, malloc(4 * sizeof(int)), 4, membuf_realloc);
	errno = 0;
	membuf_prepare_space(&mb, num_extra);
	ok1(membuf_num_space(&mb) < num_extra);
	ok1(errno == ENOMEM);
	free(membuf_cleanup(&mb));

	/* Same, from the documented empty-NULL initial state. */
	membuf_init(&mb, NULL, 0, membuf_realloc);
	errno = 0;
	membuf_prepare_space(&mb, num_extra);
	ok1(membuf_num_space(&mb) < num_extra);
	free(membuf_cleanup(&mb));

	return exit_status();
}
