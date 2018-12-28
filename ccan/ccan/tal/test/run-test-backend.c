#include <stdlib.h>
#include <stdbool.h>

/* Make sure it always uses our allocation/resize/free fns! */
static bool my_alloc_called;

static void *my_alloc(size_t len)
{
	my_alloc_called = true;
	return (char *)malloc(len + 16) + 16;
}

static void my_free(void *p)
{
	if (p)
		free((char *)p - 16);
}

static void *my_realloc(void *old, size_t new_size)
{
	return (char *)realloc((char *)old - 16, new_size + 16) + 16;
}

#define free ((void (*)(void *))abort)
#define malloc ((void *(*)(size_t))abort)
#define realloc ((void *(*)(void *, size_t))abort)

#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

#define NUM_ALLOCS 1000

static void destroy_p(void *p UNNEEDED)
{
}

int main(void)
{
	void *p, *c[NUM_ALLOCS];
	int i;
	char *name;

	/* Mostly we rely on the allocator (or valgrind) crashing. */
	plan_tests(1);

	tal_set_backend(my_alloc, my_realloc, my_free, NULL);

	p = tal(NULL, char);
	ok1(my_alloc_called);

	/* Adding properties makes us allocated. */
	tal_add_destructor(p, destroy_p);

	tal_set_name(p, "test");
	name = tal_arr(NULL, char, 6);
	strcpy(name, "test2");
	tal_set_name(p, name);
	/* makes us free old name */
	tal_set_name(p, name);
	tal_free(name);

	/* Add lots of children. */
	for (i = 0; i < NUM_ALLOCS; i++)
		c[i] = tal(p, char);

	/* Now steal a few. */
	for (i = 1; i < NUM_ALLOCS / 2; i++)
		tal_steal(c[0], c[i]);

	/* Now free individual ones.. */
	for (i = NUM_ALLOCS / 2; i < NUM_ALLOCS; i++)
		tal_free(c[i]);

	/* Finally, free the parent. */
	tal_free(p);

	tal_cleanup();
	return exit_status();
}
