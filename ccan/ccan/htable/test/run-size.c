#include <ccan/htable/htable.h>
#include <ccan/htable/htable.c>
#include <ccan/tap/tap.h>
#include <stdbool.h>
#include <string.h>

#define NUM_VALS 512

/* We use the number divided by two as the hash (for lots of
   collisions). */
static size_t hash(const void *elem, void *unused)
{
	size_t h = *(uint64_t *)elem / 2;
	return h;
}

int main(int argc, char *argv[])
{
	struct htable ht;
	uint64_t val[NUM_VALS];
	unsigned int i;

	plan_tests((NUM_VALS) * 2);
	for (i = 0; i < NUM_VALS; i++)
		val[i] = i;

	htable_init(&ht, hash, NULL);
	for (i = 0; i < NUM_VALS; i++) {
		ok1(ht.max >= i);
		ok1(ht.max <= i * 2);
		htable_add(&ht, hash(&val[i], NULL), &val[i]);
	}
	htable_clear(&ht);

	return exit_status();
}
