/* Regression test: htable_init_sized() must not overflow its allocation
 * size computation.  With expect large enough to reach the bits==30 cap,
 * the size was computed as sizeof(size_t) << 30; on 32-bit (ILP32) that
 * wraps to 0, so a 0-byte allocation "succeeds", the function returns
 * true, and the first htable_add() writes out of bounds (ASan:
 * heap-buffer-overflow in ht_add()).
 *
 * The fix stops the sizing loop before the allocation size wraps (on
 * ILP32 that caps bits at 29).  This test intercepts the allocator and
 * checks the requested size against the overflow-free computation, so it
 * fails on 32-bit before the fix and passes everywhere after it.
 */
#include <ccan/htable/htable.h>
#include <ccan/htable/htable.c>
#include <ccan/tap/tap.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

static size_t hash(const void *elem, void *unused UNNEEDED)
{
	return *(size_t *)elem;
}

static size_t requested_len;
static bool saw_request;

/* Record the request; fail anything larger than 1MB. */
static void *spy_alloc(struct htable *ht, size_t len)
{
	requested_len = len;
	saw_request = true;
	if (len > 1048576)
		return NULL;
	return calloc(len, 1);
}

static void spy_free(struct htable *ht, void *p)
{
	free(p);
}

static void timeout_handler(int sig)
{
	(void)sig;
	_exit(1);
}

int main(void)
{
	struct htable ht;
	/* ht_max(bits=29) == 469762048 on both ILP32 and LP64, so this
	 * expect drives the sizing loop to its cap. */
	const size_t expect = (size_t)469762048 + 1;
	/* Overflow-free computation of the correct request: bits==30 on
	 * LP64, capped at bits==29 on ILP32 where 4 << 30 would wrap. */
	uint64_t correct = (uint64_t)sizeof(size_t) << 30;

	if (correct > (uint64_t)SIZE_MAX)
		correct = (uint64_t)sizeof(size_t) << 29;

	alarm(10);
	signal(SIGALRM, timeout_handler);

	plan_tests(2);
	htable_set_allocator(spy_alloc, spy_free);

	htable_init_sized(&ht, hash, NULL, expect);
	ok1(saw_request);
	ok((uint64_t)requested_len == correct,
	   "alloc size at sizing cap: requested %zu, correct %llu",
	   requested_len, (unsigned long long)correct);

	htable_clear(&ht);
	htable_set_allocator(NULL, NULL);
	return exit_status();
}
