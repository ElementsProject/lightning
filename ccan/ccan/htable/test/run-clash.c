#include <ccan/htable/htable.h>
#include <ccan/htable/htable.c>
#include <ccan/tap/tap.h>
#include <stdbool.h>
#include <string.h>

/* Clashy hash */
static size_t hash(const void *elem, void *unused UNNEEDED)
{
	return 0;
}

int main(void)
{
	struct htable ht;

	plan_tests(254 * 253);
	/* We try to get two elements which clash */
	for (size_t i = 2; i < 256; i++) {
		for (size_t j = 2; j < 256; j++) {
			if (i == j)
				continue;
			htable_init(&ht, hash, NULL);
			htable_add(&ht, hash((void *)i, NULL), (void *)i);
			htable_add(&ht, hash((void *)j, NULL), (void *)j);
			ok1(htable_check(&ht, "test"));
			htable_clear(&ht);
		}
	}
	return exit_status();
}
