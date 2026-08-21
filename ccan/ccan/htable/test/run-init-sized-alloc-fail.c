/* Regression test: htable_init_sized() allocation-failure path must leave
 * the htable in a consistent (empty) state, as documented:
 * "If this returns false, @ht is still usable" (htable.h).
 *
 * Before the fix, ht->bits was left at the computed value while ht->table
 * pointed at the singleton &ht->common_bits, so the next htable_add()
 * indexed up to (1<<bits)-1 buckets into a one-bucket "table" and wrote
 * out of bounds (ASan: stack/heap-buffer-overflow in ht_add()).
 */
#include <unistd.h>
#include <ccan/htable/htable.h>
#include <ccan/htable/htable.c>
#include <ccan/tap/tap.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

static size_t hash(const void *elem, void *unused UNNEEDED)
{
	return *(size_t *)elem;
}

static bool cmp(const void *candidate, void *ptr)
{
	return *(const size_t *)candidate == *(const size_t *)ptr;
}

/* Fail any allocation larger than 64 bytes. */
static void *fail_alloc(struct htable *ht, size_t len)
{
	if (len > 64)
		return NULL;
	return calloc(len, 1);
}

static void fail_free(struct htable *ht, void *p)
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
	size_t val = 3;

	alarm(10);
	signal(SIGALRM, timeout_handler);

	plan_tests(5);
	htable_set_allocator(fail_alloc, fail_free);

	/* expect=1000 -> bits=11 -> needs 16KB -> allocation fails. */
	ok1(!htable_init_sized(&ht, hash, NULL, 1000));

	/* Must be a consistent empty table: singleton table means bits == 0. */
	ok1(ht.table == &ht.common_bits);
	ok1(ht.bits == 0);

	if (ht.bits == 0) {
		/* Documented as still usable: this must not corrupt memory. */
		ok1(htable_add(&ht, hash(&val, NULL), &val));
		ok1(htable_get(&ht, hash(&val, NULL), cmp, &val) == &val);
	} else {
		/* Adding now would write out of bounds; fail safely. */
		ok(0, "htable unusable after failed htable_init_sized (bits=%u)",
		   ht.bits);
		ok(0, "skipping add which would write out of bounds");
	}

	htable_clear(&ht);
	htable_set_allocator(NULL, NULL);
	return exit_status();
}
