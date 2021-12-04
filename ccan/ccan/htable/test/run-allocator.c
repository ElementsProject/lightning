/* Include the C files directly. */
#include <ccan/htable/htable.h>
#include <ccan/htable/htable.c>
#include <ccan/tap/tap.h>
#include <stdbool.h>
#include <string.h>

struct htable_with_counters {
	struct htable ht;
	size_t num_alloc, num_free;
};

static void *test_alloc(struct htable *ht, size_t len)
{
	((struct htable_with_counters *)ht)->num_alloc++;
	return calloc(len, 1);
}

	
static void test_free(struct htable *ht, void *p)
{
	if (p) {
		((struct htable_with_counters *)ht)->num_free++;
		free(p);
	}
}

static size_t hash(const void *elem, void *unused UNNEEDED)
{
	return *(size_t *)elem;
}

int main(void)
{
	struct htable_with_counters htc;
	size_t val[] = { 0, 1 };

	htc.num_alloc = htc.num_free = 0;
	plan_tests(12);

	htable_set_allocator(test_alloc, test_free);
	htable_init(&htc.ht, hash, NULL);
	htable_add(&htc.ht, hash(&val[0], NULL), &val[0]);
	ok1(htc.num_alloc == 1);
	ok1(htc.num_free == 0);
	/* Adding another increments, then frees old */
	htable_add(&htc.ht, hash(&val[1], NULL), &val[1]);
	ok1(htc.num_alloc == 2);
	ok1(htc.num_free == 1);
	htable_clear(&htc.ht);
	ok1(htc.num_alloc == 2);
	ok1(htc.num_free == 2);

	/* Should restore defaults */
	htable_set_allocator(NULL, NULL);
	ok1(htable_alloc == htable_default_alloc);
	ok1(htable_free == htable_default_free);

	htable_init(&htc.ht, hash, NULL);
	htable_add(&htc.ht, hash(&val[0], NULL), &val[0]);
	ok1(htc.num_alloc == 2);
	ok1(htc.num_free == 2);
	htable_add(&htc.ht, hash(&val[1], NULL), &val[1]);
	ok1(htc.num_alloc == 2);
	ok1(htc.num_free == 2);
	htable_clear(&htc.ht);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
