#define CCAN_TAL_DEBUG
#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static size_t num_allocated;

static void *alloc_account(size_t len)
{
	num_allocated++;
	return malloc(len);
}

static void free_account(void *p)
{
	num_allocated--;
	return free(p);
}

#define NUM_ALLOCS 1000

int main(void)
{
	void *p, *c[NUM_ALLOCS];
	int i;
	size_t allocated_after_first;

	plan_tests(1);

	tal_set_backend(alloc_account, NULL, free_account, NULL);

	p = tal(NULL, char);
	c[0] = tal(p, char);

	allocated_after_first = num_allocated;
	for (i = 1; i < NUM_ALLOCS; i++)
		c[i] = tal(p, char);

	/* Now free them all. */
	for (i = 0; i < NUM_ALLOCS; i++)
		tal_free(c[i]);

	/* We can expect some residue from having any child, but limited! */
	ok1(num_allocated <= allocated_after_first);
	tal_free(p);
	tal_cleanup();
	return exit_status();
}
