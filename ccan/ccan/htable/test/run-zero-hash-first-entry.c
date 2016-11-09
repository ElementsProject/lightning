#include <ccan/htable/htable.h>
#include <ccan/htable/htable.c>
#include <ccan/tap/tap.h>
#include <stdbool.h>

struct data {
	size_t key;
};

/* Hash is simply key itself. */
static size_t hash(const void *e, void *unused UNNEEDED)
{
	struct data *d = (struct data *)e;

	return d->key;
}

static bool eq(const void *e, void *k)
{
	struct data *d = (struct data *)e;
	size_t *key = (size_t *)k;

	return (d->key == *key);
}

int main(void)
{
	struct htable table;
	struct data *d0, *d1;

	plan_tests(6);

	d1 = malloc(sizeof(struct data));
	d1->key = 1;
	d0 = malloc(sizeof(struct data));
	d0->key = 0;

	htable_init(&table, hash, NULL);

	htable_add(&table, d0->key, d0);
	htable_add(&table, d1->key, d1);

	ok1(table.elems == 2);
	ok1(htable_get(&table, 1, eq, &d1->key) == d1);
	ok1(htable_get(&table, 0, eq, &d0->key) == d0);
	htable_clear(&table);

	/* Now add in reverse order, should still be OK. */
	htable_add(&table, d1->key, d1);
	htable_add(&table, d0->key, d0);

	ok1(table.elems == 2);
	ok1(htable_get(&table, 1, eq, &d1->key) == d1);
	ok1(htable_get(&table, 0, eq, &d0->key) == d0);
	htable_clear(&table);

	free(d0);
	free(d1);
	return exit_status();
}
  
