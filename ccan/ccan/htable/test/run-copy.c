#include <ccan/htable/htable.h>
#include <ccan/htable/htable.c>
#include <ccan/tap/tap.h>
#include <stdbool.h>
#include <string.h>

#define NUM_VALS 512

static size_t hash(const void *elem, void *unused UNNEEDED)
{
	size_t h = *(uint64_t *)elem / 2;
	return h;
}

static bool cmp(const void *candidate, void *ptr)
{
	return *(const uint64_t *)candidate == *(const uint64_t *)ptr;
}

int main(void)
{
	struct htable ht, ht2;
	uint64_t val[NUM_VALS], i;

	plan_tests((NUM_VALS) * 3);
	for (i = 0; i < NUM_VALS; i++)
		val[i] = i;

	htable_init(&ht, hash, NULL);
	for (i = 0; i < NUM_VALS; i++) {
		ok1(ht_max(&ht) >= i);
		ok1(ht_max(&ht) <= i * 2);
		htable_add(&ht, hash(&val[i], NULL), &val[i]);
	}

	htable_copy(&ht2, &ht);
	htable_clear(&ht);

	for (i = 0; i < NUM_VALS; i++)
		ok1(htable_get(&ht2, hash(&i, NULL), cmp, &i) == &val[i]);
	htable_clear(&ht2);

	return exit_status();
}
