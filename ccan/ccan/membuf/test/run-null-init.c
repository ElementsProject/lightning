/* Temporary auditor regression test (kimi-code audit, 2026-08-05).
 * Exercises the documented empty-NULL initialization idiom
 * (membuf.h:48: membuf_init(&intp_membuf, NULL, 0, membuf_realloc)).
 * Passes in plain builds; aborts under UBSan today because
 * membuf_elems_/membuf_space_ compute NULL + 0 (membuf.h:86,133) and
 * membuf_prepare_space_ subtracts NULL (membuf.c:54).
 * After repair it must run UBSan-clean.
 */
#include <ccan/membuf/membuf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Include the C file directly. */
#include <ccan/membuf/membuf.c>
#include <ccan/tap/tap.h>

int main(void)
{
	MEMBUF(int) mb;
	int *p;
	size_t delta;

	plan_tests(7);
	alarm(10);

	membuf_init(&mb, NULL, 0, membuf_realloc);
	ok1(membuf_num_elems(&mb) == 0);
	ok1(membuf_num_space(&mb) == 0);
	ok1(membuf_elems(&mb) == NULL);

	/* Grow from NULL; fill, consume, verify. */
	delta = membuf_prepare_space(&mb, 4);
	ok1(membuf_num_space(&mb) >= 4);
	(void)delta;
	p = membuf_space(&mb);
	for (int i = 0; i < 4; i++)
		p[i] = i + 1;
	membuf_added(&mb, 4);
	ok1(membuf_num_elems(&mb) == 4);
	ok1(memcmp(membuf_elems(&mb), (int[]){1, 2, 3, 4},
		   4 * sizeof(int)) == 0);
	membuf_consume(&mb, 4);
	ok1(membuf_num_elems(&mb) == 0);

	free(membuf_cleanup(&mb));
	return exit_status();
}
